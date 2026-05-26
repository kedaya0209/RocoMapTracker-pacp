"""RocoMapTracker 桥接协议 + 坐标转换

被 wrapper_server.py 和 wrapper_bridge.py 共用。
"""
from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

# ======================== 协议常量 ========================

MSG_HELLO = 1
MSG_EXTERNAL_POSITION = 210  # 已废弃，保留兼容
MSG_SCENE_CHANGE = 211
MSG_STOP_MATCHING = 212
MSG_START_MATCHING = 213
MSG_AREA_CHANGE = 214
MSG_ITEM_PICKUP = 215

# ======================== 游戏配置查找器 ========================


class BagItemDb:
    """BAG_ITEM_CONF.json 加载器：goods_id → 物品名称。"""

    def __init__(self, bag_conf_path: str | Path) -> None:
        self._path = Path(bag_conf_path)
        self._map: dict[int, str] = {}
        self._loaded = False

    def load(self) -> bool:
        if not self._path.exists():
            print(f"[!] BAG_ITEM_CONF.json 不存在: {self._path}")
            return False
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            rows = data.get("RocoDataRows", {})
            for k, v in rows.items():
                name = v.get("name", "")
                if name:
                    self._map[int(k)] = name
            self._loaded = True
            print(f"[*] 物品数据库已加载: {len(self._map)} 条")
            return True
        except Exception as e:
            print(f"[!] BAG_ITEM_CONF.json 加载失败: {e}")
            return False

    def lookup(self, goods_id: int) -> str | None:
        return self._map.get(goods_id)


class AreaFuncDb:
    """AREA_FUNC_CONF.json 加载器：area_func_conf_id → 区域名称（editor_name）。"""

    def __init__(self, assets_dir: str | Path) -> None:
        self._path = Path(assets_dir) / "AREA_FUNC_CONF.json"
        self._map: dict[int, str] = {}
        self._loaded = False

    def load(self) -> bool:
        if not self._path.exists():
            print(f"[!] AREA_FUNC_CONF.json 不存在: {self._path}")
            return False
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            rows = data.get("RocoDataRows", {})
            for k, v in rows.items():
                name = v.get("editor_name", "")
                if name:
                    self._map[int(k)] = name
            self._loaded = True
            print(f"[*] 区域数据库已加载: {len(self._map)} 条")
            return True
        except Exception as e:
            print(f"[!] AREA_FUNC_CONF.json 加载失败: {e}")
            return False

    def lookup(self, area_func_conf_id: int) -> str | None:
        return self._map.get(area_func_conf_id)

# INTERNAL 模式使用 SIFT 图（8192×8192）
DEFAULT_MAP_WIDTH = 8192
DEFAULT_MAP_HEIGHT = 8192

# ======================== 四元数 → 朝向角 ========================

_QUAT_SCALE = 10000.0


# ======================== 二进制编码 ========================


def send_msg(sock: socket.socket, msg_type: int, body: bytes | None = None) -> None:
    header = struct.pack(">ii", msg_type, len(body) if body else 0)
    sock.sendall(header + (body or b""))


def encode_hello(client_id: str = "rkpp-bridge") -> bytes:
    name_bytes = client_id.encode("utf-8")
    parts = [struct.pack(">H", len(name_bytes)), name_bytes]
    parts.append(struct.pack(">H", 0))  # provides 空
    parts.append(struct.pack(">H", 0))  # subscribes 空
    return b"".join(parts)


def encode_position(x: float, y: float, angle: float) -> bytes:
    return struct.pack(">ddd", x, y, angle % 360.0)


def encode_scene_change(scene_cfg_id: int) -> bytes:
    return struct.pack(">I", scene_cfg_id)


def encode_string(s: str) -> bytes:
    """将字符串编码为 UTF-8 字节（Python→Java 字符串协议）。"""
    return s.encode("utf-8")


def encode_area_change(area_func_conf_id: int) -> bytes:
    return struct.pack(">I", area_func_conf_id)


def encode_item_pickup(goods_id: int) -> bytes:
    return struct.pack(">I", goods_id)


# ======================== 欧拉角解码 ========================


def _decompress_quat(raw: dict) -> tuple[float, float, float, float] | None:
    """压缩四元数 {x, y, z} → (x, y, z, w)，自动推算 w。"""
    if not isinstance(raw, dict):
        return None
    rx, ry, rz = raw.get("x"), raw.get("y"), raw.get("z")
    if rx is None or ry is None or rz is None:
        return None
    x = (rx if rx < 2**31 else rx - 2**32) / _QUAT_SCALE
    y = (ry if ry < 2**31 else ry - 2**32) / _QUAT_SCALE
    z = (rz if rz < 2**31 else rz - 2**32) / _QUAT_SCALE
    w_sq = 1.0 - x*x - y*y - z*z
    w = max(0.0, w_sq) ** 0.5
    return x, y, z, w


def _quat_to_heading(x: float, y: float, z: float, w: float) -> float:
    """四元数 → 水平朝向角（度，0-360，0°=北/上，顺时针增加）。"""
    import math
    siny = 2.0 * (w * y - x * z)
    cosy = 1.0 - 2.0 * (y * y + z * z)
    deg = math.degrees(math.atan2(siny, cosy))
    # deg 是标准数学角（0°=东+90°=北），转换为 JavaFX 角（0°=北+90°=东）
    return (90 - deg) % 360.0


def extract_heading(event: dict) -> float:
    """从事件中提取水平朝向角（ctrl_rot，玩家输入方向）。

    优先使用 wrapper_server 已解码的 event['heading']；
    否则回退到原始压缩四元数解码。
    """
    pre = event.get("heading")
    if isinstance(pre, dict):
        h = pre.get("ctrl_heading")
        if h:
            return float(h)
    content = event.get("content") or {}
    rot = content.get("ctrl_rot") or event.get("ctrl_rot")
    if rot:
        q = _decompress_quat(rot)
        if q:
            return _quat_to_heading(*q)
    return 0.0


# ======================== 场景数据库 ========================


@dataclass
class SceneParams:
    """场景坐标参数。

    将游戏内场景的局部坐标（scene 坐标系）映射到世界地图的归一化坐标 [0,1]。

    映射公式：
        nx = (game_x - center_x) / side_length + 0.5
        ny = (game_y - center_y) / side_length + 0.5

    nx/ny 在 0~1 之间时表示玩家位于该场景的世界地图图块范围内。
    """
    center_x: float
    center_y: float
    side_length: float


class SceneDb:
    """场景数据库：从 scene_cfg_id 查询场景的世界地图坐标参数。

    关联两个配置文件：

    1. SCENE_CONF.json  — 场景定义，scene_cfg_id → scene_res_id
       格式：
       {
         "RocoDataRows": {
           "103": {                           ← scene_cfg_id (卡洛西亚大陆)
             "scene_res_id": 4166,            ← 关联到 WORLD_MAP_BLOCK_CONF
             "name": "卡洛西亚大陆",
             ...
           },
           "104": {
             "scene_res_id": 4167,
             ...
           }
         }
       }

    2. WORLD_MAP_BLOCK_CONF.json  — 世界地图图块定义，scene_res_id → 坐标参数
       格式：
       {
         "RocoDataRows": {
           "1": {
             "scene_res_id": 4166,
             "map_center_position_xyz": "5567.178;3874.627;0",  ← 场景中心点 (x;y;z)，z 无用
             "side_length": 2000,                                ← 场景在世界地图上的边长
             ...
           }
         }
       }

    转换流程：
        scene_cfg_id (0x0133 opcode) → SCENE_CONF → scene_res_id
        → WORLD_MAP_BLOCK_CONF → map_center_position_xyz + side_length → SceneParams
        → CoordConverter.convert() 将 game_x/game_y 映射到 8192×8192 像素图
    """

    def __init__(self, assets_dir: str | Path) -> None:
        self.assets_dir = Path(assets_dir)
        self._scene_conf: dict = {}
        self._res_id_to_block: dict[int, dict] = {}
        self._loaded = False

    def load(self) -> bool:
        scene_path = self.assets_dir / "SCENE_CONF.json"
        world_path = self.assets_dir / "WORLD_MAP_BLOCK_CONF.json"

        if not scene_path.exists():
            print(f"[!] SCENE_CONF.json 不存在: {scene_path}")
            return False
        if not world_path.exists():
            print(f"[!] WORLD_MAP_BLOCK_CONF.json 不存在: {world_path}")
            return False

        with open(scene_path, encoding="utf-8") as f:
            self._scene_conf = json.load(f)
        with open(world_path, encoding="utf-8") as f:
            world_data = json.load(f)

        for entry in world_data.get("RocoDataRows", {}).values():
            res_id = entry.get("scene_res_id")
            if res_id:
                self._res_id_to_block[int(res_id)] = entry

        self._loaded = True
        print(f"[*] 场景数据库已加载: {len(self._scene_conf.get('RocoDataRows', {}))} 场景, "
              f"{len(self._res_id_to_block)} 地图块")
        return True

    def lookup(self, scene_cfg_id: int) -> SceneParams | None:
        if not self._loaded:
            return None
        scene = self._scene_conf.get("RocoDataRows", {}).get(str(scene_cfg_id))
        if not scene:
            return None
        res_id = scene.get("scene_res_id")
        if not res_id:
            return None
        block = self._res_id_to_block.get(int(res_id))
        if not block:
            return None
        center_str = block.get("map_center_position_xyz", "")
        if not center_str:
            return None
        parts = center_str.split(";")
        if len(parts) < 2:
            return None
        return SceneParams(
            center_x=float(parts[0]),
            center_y=float(parts[1]),
            side_length=float(block.get("side_length", 1)),
        )


# ======================== 坐标转换 ========================


class CoordConverter:
    def __init__(self, calib: dict | None = None,
                 map_width: int = DEFAULT_MAP_WIDTH,
                 map_height: int = DEFAULT_MAP_HEIGHT) -> None:
        self.scale_x = calib.get("scale_x", 1.0) if calib else 1.0
        self.scale_y = calib.get("scale_y", 1.0) if calib else 1.0
        self.offset_x = calib.get("offset_x", 0.0) if calib else 0.0
        self.offset_y = calib.get("offset_y", 0.0) if calib else 0.0
        self.heading_offset = calib.get("heading_offset", 0.0) if calib else 0.0
        self.map_width = map_width
        self.map_height = map_height

    def convert(self, game_x: float, game_y: float,
                heading: float,
                scene: SceneParams | None = None) -> tuple[float, float, float]:
        if scene and scene.side_length > 0:
            nx = (game_x - scene.center_x) / scene.side_length + 0.5
            # 游戏 Y 轴朝南增加（屏幕坐标系），无需翻转
            ny = (game_y - scene.center_y) / scene.side_length + 0.5
            map_x = nx * self.map_width
            map_y = ny * self.map_height
            map_x = max(0.0, min(map_x, float(self.map_width - 1)))
            map_y = max(0.0, min(map_y, float(self.map_height - 1)))
        else:
            map_x = game_x * self.scale_x + self.offset_x
            map_y = game_y * self.scale_y + self.offset_y
        map_heading = (heading + self.heading_offset) % 360.0
        return map_x, map_y, map_heading


# ======================== RMT Socket 发送器 ========================


class RmtSender:
    """连接 RocoMapTracker SocketServer，发送各种游戏事件。"""

    def __init__(self, host: str, port: int, converter: CoordConverter,
                 scene_db: SceneDb | None = None,
                 bag_db: BagItemDb | None = None,
                 area_func_db: AreaFuncDb | None = None) -> None:
        self.host = host
        self.port = port
        self.converter = converter
        self.scene_db = scene_db
        self.bag_db = bag_db
        self.area_func_db = area_func_db
        self._sock: socket.socket | None = None
        self._connected = False
        self._current_scene_id: int | None = None
        self._current_scene_params: SceneParams | None = None

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock.settimeout(5.0)
            self._sock.connect((self.host, self.port))
            print(f"[*] RMT 已连接 {self.host}:{self.port}")
            send_msg(self._sock, MSG_HELLO, encode_hello("rkpp-bridge"))
            self._connected = True
            return True
        except Exception as e:
            print(f"[!] RMT 连接失败: {e}")
            return False

    def _try_reconnect(self) -> bool:
        """尝试重连（最多一次）。"""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connected = False
        return self.connect()

    def send_position(self, map_x: float, map_y: float, map_heading: float) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            send_msg(self._sock, MSG_EXTERNAL_POSITION,
                     encode_position(map_x, map_y, map_heading))
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_scene_change(self, scene_cfg_id: int) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            send_msg(self._sock, MSG_SCENE_CHANGE,
                     encode_scene_change(scene_cfg_id))
            print(f"[scene] RMT 场景变更: cfg_id={scene_cfg_id}", flush=True)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_area_change(self, area_func_conf_id: int) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            # 查找区域名称，找不到则 fallback 到 raw ID
            name = None
            if self.area_func_db:
                name = self.area_func_db.lookup(area_func_conf_id)
            payload = encode_string(name) if name else encode_area_change(area_func_conf_id)
            send_msg(self._sock, MSG_AREA_CHANGE, payload)
            tag = name or f"#{area_func_conf_id}"
            print(f"[area] RMT 区域变更: {tag}", flush=True)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_item_pickup(self, goods_id: int, pickup_num: int = 1, total_num: int = 0) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            name = None
            if self.bag_db:
                name = self.bag_db.lookup(goods_id)
            tag = name or f"#{goods_id}"
            # 格式: name|pickup_num|backpack_total
            payload = f"{tag}|{pickup_num}|{total_num}".encode("utf-8")
            send_msg(self._sock, MSG_ITEM_PICKUP, payload)
            print(f"[item] RMT 物资拾取: {tag} +{pickup_num} 背包:{total_num}", flush=True)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_stop_matching(self) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            send_msg(self._sock, MSG_STOP_MATCHING)
            print("[ctrl] 停止匹配", flush=True)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_start_matching(self) -> bool:
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            send_msg(self._sock, MSG_START_MATCHING)
            print("[ctrl] 开始匹配", flush=True)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 发送失败: {e}")
            self._connected = False
            return False

    def send_batch(self, items: list[tuple[int, bytes]]) -> bool:
        """批量发送多个消息（IO 线程用），失败时自动重连。"""
        if not self._connected or not self._sock:
            if not self._try_reconnect():
                return False
        try:
            buffer = bytearray()
            for service_id, body in items:
                header = struct.pack(">ii", service_id, len(body))
                buffer.extend(header)
                if body:
                    buffer.extend(body)
            self._sock.sendall(bytes(buffer))
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] RMT 批量发送失败 ({len(items)}条): {e}")
            self._connected = False
            return False

    def handle_event(self, event: dict) -> None:
        """从 relay 事件中提取位置数据并发送到 RMT。"""
        content = event.get("content") or {}

        # 场景切换
        scene_cfg_id = content.get("scene_cfg_id")
        if scene_cfg_id is not None:
            sid = int(scene_cfg_id)
            if sid != self._current_scene_id:
                self._current_scene_id = sid
                if self.scene_db:
                    self._current_scene_params = self.scene_db.lookup(sid)
                    if self._current_scene_params:
                        print(f"[scene] 场景 {sid}: "
                              f"center=({self._current_scene_params.center_x}, "
                              f"{self._current_scene_params.center_y}), "
                              f"side={self._current_scene_params.side_length}")

        # 位置更新
        to_pos = event.get("to_pos") or content.get("to_pos")
        if not to_pos:
            return
        gx = to_pos.get("x")
        gy = to_pos.get("y")
        if gx is None or gy is None:
            return

        heading = extract_heading(event)
        mx, my, mh = self.converter.convert(
            float(gx), float(gy), heading,
            scene=self._current_scene_params,
        )

        scene_tag = f"scene={self._current_scene_id}" if self._current_scene_id else "fallback"
        print(f"[move] game=({gx},{gy}) heading={heading:.0f}° "
              f"→ map=({mx:.0f},{my:.0f}) heading={mh:.0f}° [{scene_tag}]")

        self.send_position(mx, my, mh)

    def close(self) -> None:
        self._connected = False
        if self._sock:
            self._sock.close()
