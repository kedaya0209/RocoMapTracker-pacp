# RocoMapTracker-pcap

RocoMapTracker 的抓包桥接组件，监听游戏通信协议，解析场景切换、区域变更、物品拾取等事件，通过 Socket 推送到 RocoMapTracker 主程序。

## 功能

- 监听 TCP 端口（默认 8195），BPF 过滤游戏协议包
- 解析场景切换（0x0133）、区域进入/离开（0x0414）、物品拾取（0x0243）
- 物品 ID → 名称自动转换（基于 BAG_ITEM_CONF.json）
- 场景坐标 → 地图像素坐标转换
- 跨请求物品拾取合并（150ms 防抖）
- 通过 opcode 预过滤跳过 95% 无关包的解密/解析

## 使用

```bash
RocoMapTracker-pcap.exe --rmt-port <RocoMapTracker-Socket端口>
```

选项：

| 参数 | 说明 |
|------|------|
| `--rmt-port` | RocoMapTracker SocketServer 端口（必填） |
| `--iface` | 网卡名，留空自动检测 |
| `--port` | 游戏端口，默认 8195 |
| `--key` | 预设 AES 密钥，16 字节 ASCII 或 32 位 hex |
| `--assets-dir` | 游戏配置目录，默认自动检测 |

## 依赖

- Python 3.12+
- [RKPP](https://github.com/yuzeis/Roco-Kingdom-Protocol-Parser.git) — Roco Kingdom Protocol Parser，协议解析核心
- Scapy — 网络抓包
- Npcap/WinPcap — 底层抓包驱动

## 免责声明

本软件仅供学习和研究使用，禁止用于任何违反游戏用户协议的行为。

使用者需自行承担使用本软件产生的一切后果。开发者不对因使用本软件导致的任何账号封禁、数据丢失或其他损失负责。

## 原项目

RKPP (Roco Kingdom Protocol Parser) — [https://github.com/yuzeis/Roco-Kingdom-Protocol-Parser](https://github.com/yuzeis/Roco-Kingdom-Protocol-Parser)
