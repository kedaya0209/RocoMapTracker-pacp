"""场景变更嗅探器：监听 0x0133 + 0x0414 包，检测场景/区域切换并推送到 RocoMapTracker。

Pipeline: 抓包线程 → packet_pool → 解包线程(×2) → io_pool → IO线程 → Java

用法：
    python rmt_bridge.py --rmt-port 56796
"""
from __future__ import annotations

import argparse
import sys
import time
import threading
import queue
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent / "RKPP"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from scapy.all import AsyncSniffer, TCP  # type: ignore

from rkpp_network import (FlowState, decrypt_4013_body_candidates,
                           flow_key_from_packet, packet_has_target_port,
                           parse_key_text)
import rkpp_proto as proto
import rkpp_analysis as analysis

from rmt_protocol import (CoordConverter, DEFAULT_MAP_HEIGHT, DEFAULT_MAP_WIDTH,
                           RmtSender, SceneDb,
                           BagItemDb, AreaFuncDb,
                           MSG_SCENE_CHANGE, MSG_STOP_MATCHING, MSG_START_MATCHING,
                           MSG_AREA_CHANGE, MSG_ITEM_PICKUP,
                           encode_scene_change, encode_area_change, encode_string)

DEFAULT_PORT = 8195

# IO 线程刷盘间隔
IO_FLUSH_INTERVAL = 0.05  # 50ms

# 我们关心的 opcode 集合（其他 opcode 跳过完整解析）
INTERESTING_OPCODES = {0x0133, 0x0414, 0x0243}


def peek_opcode(body: bytes, direction: str) -> int | None:
    """从解密后的 0x4013 body 中预提取 opcode，不做 protobuf 解析。

    返回 opcode（int），或 None（无法识别传输层格式）。
    """
    # live_s2c: magic 0x55AA at body[4:6], opcode at body[0:4]
    if direction == "s2c" and len(body) >= 10 and body[4:6] == b"\x55\xaa":
        op = int.from_bytes(body[0:4], "big")
        return op if 0 < op <= 0xFFFF else None
    # live_c2s: magic 0x3963 at body[8:10], raw_opcode at body[4:8]
    if direction == "c2s" and len(body) >= 14:
        if body[8:10] == b"\x39\x63":
            raw = int.from_bytes(body[4:8], "big")
            if raw <= 0:
                return None
            return (raw & 0xFFFF) if (raw >> 16) in {0, 1} and (raw & 0xFFFF) else raw
        if body[8:10] == b"\x7c\xa2":
            raw = int.from_bytes(body[4:8], "big")
            if raw <= 0:
                return None
            return (raw & 0xFFFF) if (raw >> 16) in {0, 1} and (raw & 0xFFFF) else raw
    return None


class RmtBridge:
    """独立桥接器：抓 0x0133 → 提取 scene_cfg_id → 推场景变更到 RocoMapTracker。"""

    def __init__(self, iface: str, port: int, rmt_sender: RmtSender,
                 preset_key: bytes | None = None,
                 dump_path: str | None = None) -> None:
        self.iface = iface
        self.port = port
        self.rmt_sender = rmt_sender
        self.preset_key = preset_key
        self.flows: dict[tuple, FlowState] = {}
        self._sniffer: AsyncSniffer | None = None
        self._dump_file = None
        if dump_path:
            import datetime
            path = Path(dump_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._dump_file = open(path, "w", encoding="utf-8")
            self._dump_file.write(f"# Packet dump started at {datetime.datetime.now()}\n"
                                  f"# iface={iface} port={port}\n")
            self._dump_file.flush()
            print(f"[*] 包日志: {path.resolve()}")
        self._running = False
        self._current_scene_id: int | None = None
        self._current_area_func_id: int | None = None
        self._in_main_world = False
        self._main_world_scene_id = 103  # 卡洛西亚大陆

        # 全局共享 key：任一流提取到 key 后，新流可直接复用
        self._global_key: bytes | None = preset_key

        # ---- Pipeline 池 ----
        self._pool_counter = 0
        # 抓包 → 解包：原始 BE21 帧
        self._packet_pool: queue.Queue = queue.Queue()
        # 解包 → IO：已编码的 (service_id, payload_bytes)
        self._io_pool: queue.PriorityQueue = queue.PriorityQueue()

        # 拾取缓冲：跨请求按 (update_time, item_id) 合并
        self._pickup_buffer: dict[tuple, int] = {}
        self._pickup_meta: dict[tuple, tuple] = {}
        self._pickup_lock = threading.Lock()
        self._last_pickup_activity = 0.0
        self._pickup_debounce = 0.15  # 150ms 无新拾取才刷出

        # 2 个解码线程
        self._decode_workers: list[threading.Thread] = []
        for i in range(2):
            t = threading.Thread(target=self._decode_loop, daemon=True, name=f"decode-{i}")
            self._decode_workers.append(t)

        # 1 个 IO 线程
        self._io_thread = threading.Thread(target=self._io_loop, daemon=True, name="io-writer")

        # 统计（只累加，不 I/O）
        self._stat_total = 0
        self._stat_4013 = 0
        self._stat_0133 = 0
        self._stat_scene = 0
        self._stat_io_sent = 0
        # 流健康检测：记录最后一次成功解出 BE21 的时间
        self._flow_last_frame: dict[tuple, float] = {}
        # 流首次收包时间：用于检测从未解出 BE21 的卡死流
        self._flow_first_packet: dict[tuple, float] = {}

        # 如果流有包在收但超过 N 秒没解出 BE21，判定为卡死需要重建
        self._flow_stall_sec = 30
        # 定期重建流（释放 FlowState 内部累积的 TCP 重组缓冲区）
        self._flow_rebuild_interval = 300  # 5 分钟
        self._last_flow_rebuild = time.monotonic()

    # ------------------------------------------------------------------
    # 包入口（在 scapy 抓包线程中调用，必须快速返回）
    # ------------------------------------------------------------------

    def _on_packet(self, packet) -> None:
        try:
            self._process_packet(packet)
        except Exception as e:
            print(f"[!] _on_packet 异常: {type(e).__name__}: {e}", flush=True)

    def _process_packet(self, packet) -> None:
        if not packet_has_target_port(packet, self.port):
            return
        self._stat_total += 1
        if not packet.haslayer(TCP):
            return
        payload = bytes(packet[TCP].payload)
        if not payload:
            return
        fi = flow_key_from_packet(packet, self.port)
        if fi is None:
            return
        client_ip, direction, client_port, server_ip, server_port, flow_text = fi
        fk = (client_ip, client_port, server_ip, server_port)

        now = time.monotonic()

        # 获取或创建流
        flow = self.flows.get(fk)
        if flow is None:
            self._flow_first_packet[fk] = now
            flow = FlowState(
                flow_id=flow_text, client_ip=client_ip, client_port=client_port,
                server_ip=server_ip, server_port=server_port, key=self._global_key,
            )
            self.flows[fk] = flow

        seq = int(packet[TCP].seq)
        try:
            frame_count = 0
            cap_ts = time.monotonic()
            for be21 in flow.direction_state(direction).feed(seq, payload):
                self._pool_counter += 1
                # packet_pool 按 cap_ts 排序，确保同一流的帧按捕获顺序处理
                self._packet_pool.put((be21, flow, fk, cap_ts))
                frame_count += 1
            if frame_count > 0:
                self._flow_last_frame[fk] = now
        except Exception:
            pass  # feed 异常（如乱序严重）也不阻塞抓包

        # 检测流是否卡死：有包在收但解不出 BE21
        last_frame = self._flow_last_frame.get(fk, 0)
        first_pkt = self._flow_first_packet.get(fk, now)
        stalled = (
            # 曾产出过帧但停滞
            (last_frame > 0 and now - last_frame > self._flow_stall_sec) or
            # 从未产出过帧但已收包超时
            (last_frame == 0 and now - first_pkt > self._flow_stall_sec)
        )
        if stalled:
            # 这个流卡死了，重建
            age = now - (last_frame if last_frame > 0 else first_pkt)
            print(f"[*] 流 {fk[-1]} 卡死 ({age:.0f}s 无帧)，重建", flush=True)
            self.flows.pop(fk, None)
            self._flow_last_frame.pop(fk, None)
            self._flow_first_packet.pop(fk, None)
            # 用新流立即处理当前包
            flow = FlowState(
                flow_id=flow_text, client_ip=client_ip, client_port=client_port,
                server_ip=server_ip, server_port=server_port, key=self._global_key,
            )
            self.flows[fk] = flow
            self._flow_first_packet[fk] = now
            cap_ts = time.monotonic()
            for be21 in flow.direction_state(direction).feed(seq, payload):
                self._pool_counter += 1
                self._packet_pool.put((be21, flow, fk, cap_ts))

    # ------------------------------------------------------------------
    # 解码线程（2 个）：packet_pool → 解码 → io_pool
    # ------------------------------------------------------------------

    def _decode_loop(self) -> None:
        """从 packet_pool 取帧，解码，结果放入 io_pool。"""
        while self._running:
            try:
                be21, flow, fk, cap_ts = self._packet_pool.get(timeout=1.0)
                try:
                    self._handle_be21(be21, flow, fk, cap_ts)
                except Exception as e:
                    print(f"[!] _handle_be21 异常: {e}", flush=True)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] decode 循环异常: {e}", flush=True)
                continue

    def _push_io(self, service_id: int, payload: bytes, cap_ts: float | None = None) -> None:
        """解码线程将已编码消息投递到 io_pool。"""
        self._pool_counter += 1
        ts = cap_ts if cap_ts is not None else time.monotonic()
        self._io_pool.put((ts, self._pool_counter, service_id, payload))

    def _handle_be21(self, be21, flow, fk, cap_ts: float) -> None:
        # 密钥提取
        if be21.cmd == 0x1002 and len(be21.header_extra) >= 18:
            flow.key = be21.header_extra[2:18]
            self._global_key = flow.key
            for f in self.flows.values():
                if f.key is None:
                    f.key = self._global_key

        # 只处理加密业务包
        if be21.cmd != 0x4013:
            return

        # 确保有 key
        if flow.key is None:
            if self._global_key is not None:
                flow.key = self._global_key
            else:
                return
        self._stat_4013 += 1

        # 尝试解密
        try:
            candidates = decrypt_4013_body_candidates(flow.key, be21.body)
            if not candidates and self._global_key is not None and flow.key != self._global_key:
                flow.key = self._global_key
                candidates = decrypt_4013_body_candidates(flow.key, be21.body)
        except ValueError:
            if self._global_key is not None and flow.key != self._global_key:
                flow.key = self._global_key
                try:
                    candidates = decrypt_4013_body_candidates(flow.key, be21.body)
                except ValueError:
                    return
            else:
                return

        for mode, iv, cipher, plain in candidates:
            try:
                # 预提取 opcode，跳过不关心的包（~95% 不用解析 protobuf）
                opcode = peek_opcode(plain, be21.direction)
                if opcode is None or opcode not in INTERESTING_OPCODES:
                    continue

                pkt_dict = {
                    "cmd": 0x4013, "cmd_hex": "0x4013",
                    "direction": be21.direction,
                    "seq": be21.seq,
                    "body_len": be21.body_len,
                    "header_extra_hex": be21.header_extra.hex(),
                    "decrypted_body_hex": plain.hex(),
                }
                record = proto.parse_record(pkt_dict)
                if record is None:
                    continue

                schema_result = analysis.decode_record(record)
                decoded = (schema_result or {}).get("decoded") or {}
                if self._dump_file:
                    self._dump_file.write(
                        f"opcode=0x{opcode:04X}  "
                        f"body={plain.hex()[:120]}\n"
                    )
                    self._dump_file.flush()

                if opcode != 0x0133:
                    self._handle_non_scene(opcode, decoded, cap_ts)
                    continue
                self._stat_0133 += 1

                scene_cfg_id = decoded.get("scene_cfg_id")
                if scene_cfg_id is None:
                    continue

                sid = int(scene_cfg_id)
                if sid != self._current_scene_id:
                    self._current_scene_id = sid
                    self._stat_scene += 1
                    is_main = (sid == self._main_world_scene_id)
                    if is_main and not self._in_main_world:
                        self._in_main_world = True
                        print(f"[ctrl] 进入卡洛西亚大陆 → 开始匹配", flush=True)
                        self._push_io(MSG_START_MATCHING, b"", cap_ts)
                    elif not is_main and self._in_main_world:
                        self._in_main_world = False
                        print(f"[ctrl] 离开卡洛西亚大陆 (scene={sid}) → 停止匹配", flush=True)
                        self._push_io(MSG_STOP_MATCHING, b"", cap_ts)
                    else:
                        print(f"[scene] cfg_id={sid}", flush=True)
                        self._push_io(MSG_SCENE_CHANGE, encode_scene_change(sid), cap_ts)
                return
            except Exception as e:
                print(f"[!] 解析 opcode=0x{opcode:04X} 异常: {e}", flush=True)
                continue

    def _handle_non_scene(self, opcode: int, decoded: dict, cap_ts: float) -> None:
        # 0x0414：区域进出事件
        if opcode == 0x0414:
            acts = decoded.get("acts") or []
            for act in acts:
                if not isinstance(act, dict):
                    continue
                catcher = act.get("enterted_catcher")
                if isinstance(catcher, dict):
                    afid = catcher.get("area_func_conf_id")
                    if afid is not None:
                        afid = int(afid)
                        if afid != self._current_area_func_id:
                            self._current_area_func_id = afid
                            print(f"[area] func_id={afid}", flush=True)
                            # IO 线程发送
                            if self.rmt_sender.area_func_db:
                                name = self.rmt_sender.area_func_db.lookup(afid)
                                payload = encode_string(name) if name else encode_area_change(afid)
                            else:
                                payload = encode_area_change(afid)
                            self._push_io(MSG_AREA_CHANGE, payload, cap_ts)
                l_catcher = act.get("left_catcher")
                if isinstance(l_catcher, dict):
                    afid = l_catcher.get("area_func_conf_id")
                    if afid is not None:
                        print(f"[area] leave func_id={int(afid)}", flush=True)

        # 0x0243：场景物资拾取（缓冲到 IO 线程按 update_time 合并）
        if opcode == 0x0243:
            ret_info = decoded.get("ret_info") or {}
            goods_reward = ret_info.get("goods_reward") or {}
            rewards = goods_reward.get("rewards") or []
            changes = ret_info.get("goods_change_info", {}).get("changes") or []

            # 从 bag_item 提取 update_time
            update_times: dict[int, int] = {}
            for change in changes:
                bag_item = change.get("bag_item") or {}
                bid = bag_item.get("id")
                if bid is not None:
                    update_times[int(bid)] = int(bag_item.get("update_time", 0))

            for reward in rewards:
                item_id = reward.get("id")
                if item_id is None:
                    continue
                item_id = int(item_id)
                pickup_num = int(reward.get("num", 1))
                # 背包总量
                total_num = 0
                for change in changes:
                    bag_item = change.get("bag_item") or {}
                    if bag_item.get("id") == item_id:
                        total_num = int(bag_item.get("num", 0))
                        break
                ut = update_times.get(item_id, 0)
                key = (ut, item_id)
                tag = f"#{item_id}"
                if self.rmt_sender.bag_db:
                    name = self.rmt_sender.bag_db.lookup(item_id)
                    if name:
                        tag = name
                with self._pickup_lock:
                    self._pickup_buffer[key] = self._pickup_buffer.get(key, 0) + pickup_num
                    self._pickup_meta[key] = (tag, total_num)
            self._last_pickup_activity = time.monotonic()
            return

    # ------------------------------------------------------------------
    # IO 线程：io_pool → 批量发送 → Java
    # ------------------------------------------------------------------

    def _rebuild_flows_periodic(self) -> None:
        """定期重建 FlowState，释放内部累积的 TCP 重组缓冲区。"""
        now = time.monotonic()
        if now - self._last_flow_rebuild < self._flow_rebuild_interval:
            return
        self._last_flow_rebuild = now
        count = len(self.flows)
        if count == 0:
            return
        self.flows.clear()
        self._flow_last_frame.clear()
        self._flow_first_packet.clear()
        print(f"[*] 重建 {count} 个流，释放 TCP 重组缓冲区", flush=True)

    def _io_loop(self) -> None:
        """每 50ms 清空 io_pool + 定期重建流释放内存。"""
        while self._running:
            time.sleep(IO_FLUSH_INTERVAL)
            if not self._running:
                break
            self._rebuild_flows_periodic()
            self._flush_io()

    def _flush_io(self) -> None:
        """清空 io_pool + 拾取缓冲，批量发送。"""
        items: list[tuple[int, bytes]] = []

        # 1. io_pool 常规消息（场景/区域变更等）
        while not self._io_pool.empty():
            try:
                _, _, service_id, payload = self._io_pool.get_nowait()
                items.append((service_id, payload))
            except queue.Empty:
                break

        # 2. 拾取缓冲（debounce 150ms，让同批拾取有机会合并）
        if self._pickup_buffer:
            now = time.monotonic()
            if now - self._last_pickup_activity > self._pickup_debounce:
                with self._pickup_lock:
                    for key, count in self._pickup_buffer.items():
                        ut, item_id = key
                        tag, total = self._pickup_meta[key]
                        payload = f"{tag}|{count}|{total}".encode("utf-8")
                        items.append((MSG_ITEM_PICKUP, payload))
                    self._pickup_buffer.clear()
                    self._pickup_meta.clear()

        if not items:
            return
        self._stat_io_sent += len(items)
        if not self.rmt_sender.send_batch(items):
            pass  # send_batch 内部已处理重连

    def _workers_alive(self) -> tuple[int, int, bool]:
        """返回 (解码存活数, 解码总数, IO 线程存活)。"""
        if not self._decode_workers:
            return (0, 0, False)
        alive = sum(1 for t in self._decode_workers if t.is_alive())
        io_alive = self._io_thread is not None and self._io_thread.is_alive()
        return (alive, len(self._decode_workers), io_alive)

    def _print_health(self) -> None:
        """输出线程和流健康状态。"""
        sniffer_alive = self._sniffer is not None and getattr(self._sniffer, 'running', False)
        wa, wt, io_alive = self._workers_alive()
        cap_str = self._fmt_time(self._last_capture_time)
        dec_str = self._fmt_time(self._last_decode_time)
        print(
            f"[health] 抓包池={self._packet_pool.qsize()}  "
            f"IO池={self._io_pool.qsize()}  "
            f"流={len(self.flows)}  "
            f"嗅探器={'运行' if sniffer_alive else '停止'}  "
            f"解码={wa}/{wt}  "
            f"IO={'运行' if io_alive else '停止'}  "
            f"包总={self._stat_total}  "
            f"4013={self._stat_4013}  "
            f"0133={self._stat_0133}  "
            f"场景变更={self._stat_scene}  "
            f"IO发送={self._stat_io_sent}  "
            f"最后抓包={cap_str}  "
            f"最后解包={dec_str}",
            flush=True,
        )
        self._dump_timing()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        bpf = f"tcp port {self.port}"
        for t in self._decode_workers:
            t.start()
        self._io_thread.start()
        self._sniffer = AsyncSniffer(
            iface=self.iface, store=False, prn=self._on_packet,
            lfilter=lambda pkt: packet_has_target_port(pkt, self.port),
            filter=bpf,
        )
        self._sniffer.start()
        print(f"[*] 场景监听已启动: iface={self.iface} port={self.port}  "
              f"解码线程={len(self._decode_workers)} IO线程=1", flush=True)

    def stop(self) -> None:
        self._running = False
        if self._dump_file:
            self._dump_file.close()
            self._dump_file = None
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def wait(self) -> None:
        try:
            while self._running:
                time.sleep(2.0)
                # 检查嗅探器线程是否还活着
                if (self._sniffer is not None
                        and not getattr(self._sniffer, 'running', False)
                        and self._running):
                    print("[!] 嗅探器已停止，尝试重启", flush=True)
                    self._sniffer = AsyncSniffer(
                        iface=self.iface, store=False, prn=self._on_packet,
                        lfilter=lambda pkt: packet_has_target_port(pkt, self.port),
                        filter=f"tcp port {self.port}",
                    )
                    self._sniffer.start()
                # 检查解码线程
                wa, wt, io_alive = self._workers_alive()
                if self._running and wa == 0:
                    print("[!] 所有解码线程已停止，无法恢复，退出", flush=True)
                    self._running = False
                elif self._running and wa < wt:
                    print(f"[!] 解码线程 {wa}/{wt} 存活，部分降级", flush=True)
                if self._running and not io_alive:
                    print("[!] IO 线程已停止，无法恢复，退出", flush=True)
                    self._running = False
        except KeyboardInterrupt:
            pass


# -----------------------------------------------------------------------
# main
# -----------------------------------------------------------------------

def auto_detect_iface() -> str:
    from scapy.all import conf
    try:
        route = conf.route.route("0.0.0.0")
        iface_name = route[0]
        if iface_name:
            iface_obj = conf.ifaces.get(iface_name)
            ip = getattr(iface_obj, "ip", "?") if iface_obj else "?"
            print(f"[*] 自动选择网卡: {iface_name} (IP: {ip})")
            return str(iface_name)
    except Exception:
        pass
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", None)
        name = getattr(iface, "name", "") or ""
        if ip and ip != "127.0.0.1":
            print(f"[*] 自动选择网卡: {name} (IP: {ip})")
            return name
    print("[!] 未找到可用网卡，请用 --iface 手动指定")
    sys.exit(1)


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="轻量 RMT 桥接器")
    parser.add_argument("--iface", help="网卡名（留空自动检测）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="游戏端口")
    parser.add_argument("--key", help="已知 key，16字节ASCII或32位hex")
    parser.add_argument("--rmt-port", type=int, default=0, required=True,
                        help="RocoMapTracker SocketServer 端口")
    parser.add_argument("--dump", type=str,
                        help="全量包日志路径（用于逆向分析新 opcode）")
    parser.add_argument("--assets-dir", type=str,
                        default=str(Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)) / "assert"),
                        help="游戏配置目录")
    parser.add_argument("--bag-conf", type=str, default=None,
                        help="BAG_ITEM_CONF.json 路径，默认 <assets-dir>/BAG_ITEM_CONF.json")
    parser.add_argument("--map-width", type=int, default=DEFAULT_MAP_WIDTH)
    parser.add_argument("--map-height", type=int, default=DEFAULT_MAP_HEIGHT)
    args = parser.parse_args()

    args.iface = args.iface or auto_detect_iface()
    preset_key = parse_key_text(args.key) if args.key else None

    scene_db = SceneDb(args.assets_dir)
    scene_db.load()

    bag_conf_path = Path(args.bag_conf) if args.bag_conf else Path(args.assets_dir) / "BAG_ITEM_CONF.json"
    bag_db = BagItemDb(bag_conf_path)
    bag_db.load()
    area_func_db = AreaFuncDb(args.assets_dir)
    area_func_db.load()

    converter = CoordConverter(map_width=args.map_width, map_height=args.map_height)
    rmt_sender = RmtSender("127.0.0.1", args.rmt_port, converter, scene_db,
                           bag_db=bag_db, area_func_db=area_func_db)
    if not rmt_sender.connect():
        print("[!] RMT 连接失败，退出")
        sys.exit(1)

    bridge = RmtBridge(args.iface, args.port, rmt_sender, preset_key,
                       dump_path=args.dump)
    bridge.start()

    try:
        bridge.wait()
    except KeyboardInterrupt:
        pass
    finally:
        bridge.stop()
        rmt_sender.close()
        print("[*] 已停止")


if __name__ == "__main__":
    main()
