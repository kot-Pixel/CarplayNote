#!/usr/bin/env python3
"""从 pcap 里解析 MainScreen / AltScreen，并解开 VideoFrame 载荷。

每一帧是 128 字节明文 AirPlayScreenHeader，再加 bodySize 字节。
VideoFrame 的载荷是 ChaCha20-Poly1305：帧头是认证数据，末尾 16 字节是 tag，
nonce 从 0 起，只在视频帧上加 1。密钥是 stream_<id>_output。

解开后是 HEVC/H.264 的长度前缀码流，不是 RTP。

用法:
  python parse_screen_pcap.py hostapd11.pcap --keys all_carplay_pair_verify_keys.txt
  python parse_screen_pcap.py hostapd11.pcap --port 51077
  python parse_screen_pcap.py all_capture.pcap --port 57005 --annexb screen.h265
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from decrypt_carplay import aead_open
from parse_setup_pcap import fmt_ts, iter_pcap_packets, reassemble, tcp_payload, ts_at


HEADER_LEN = 128
MAX_BODY = 8 * 1024 * 1024
# pack(2) 的 ImageDescriptionBase，后面紧跟扩展 atom（size + 'hvcC'/'avcC'）。
IMAGE_DESC_LEN = 86
START_CODE = b"\x00\x00\x00\x01"

OPCODES = {
    0: "VideoFrame",
    1: "VideoConfig",
    2: "KeepAlive",
    3: "ForceKeyFrame",
    4: "Ignore",
    5: "KeepAliveWithBody",
}

FLAGS = (
    (1 << 0, "ShowHUD"),
    (1 << 1, "RespectTimestamps"),
    (1 << 2, "Encrypted"),
    (1 << 3, "UseFormatDescription"),
    (1 << 5, "Suspended"),
    (1 << 6, "ClearScreen"),
    (1 << 7, "InterestingFrame"),
)


def flag_names(value: int):
    names = [name for bit, name in FLAGS if value & bit]
    return names


def parse_header(raw: bytes):
    body_size, opcode = struct.unpack_from("<IB", raw, 0)
    small = raw[5:8]
    params = raw[8:128]
    info = {
        "bodySize": body_size,
        "opcode": opcode,
        "opcodeName": OPCODES.get(opcode, f"Unknown({opcode})"),
        "smallParam": list(small),
    }
    if opcode == 0:
        (pts,) = struct.unpack_from("<Q", params, 0)
        (reencode,) = struct.unpack_from("<I", params, 16)
        info["pts"] = pts
        info["reencodeCount"] = reencode
    elif opcode == 1:
        width, height = struct.unpack_from("<ff", params, 8)
        origin_x, origin_y = struct.unpack_from("<ff", params, 24)
        view_w, view_h = struct.unpack_from("<ff", params, 32)
        info["flags"] = small[1]
        info["flagNames"] = flag_names(small[1])
        info["width"] = width
        info["height"] = height
        info["viewAreaOriginX"] = origin_x
        info["viewAreaOriginY"] = origin_y
        info["viewAreaWidth"] = view_w
        info["viewAreaHeight"] = view_h
    return info


def load_output_keys(path: Path):
    keys = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if not name.startswith("stream_") or not name.endswith("_output"):
            continue
        raw = bytes.fromhex(value.strip())
        if len(raw) != 32:
            raise ValueError(f"{name} 不是 32 字节")
        keys[name] = raw
    return keys


def decrypt_video(key: bytes, nonce: int, header: bytes, body: bytes):
    if len(body) < 16:
        raise ValueError("body 短于 tag")
    return aead_open(key, nonce.to_bytes(8, "little"), header, body[:-16], body[-16:])


def describe_plain(plain: bytes):
    if len(plain) >= 12 and (plain[0] & 0xC0) == 0x80:
        return "像 RTP"
    if len(plain) >= 5:
        nal_len = struct.unpack_from(">I", plain, 0)[0]
        if 0 < nal_len <= len(plain) - 4:
            nal_type = (plain[4] >> 1) & 0x3F
            return f"HEVC 长度前缀 NAL，首个长度={nal_len} type={nal_type}"
    return "明文"


def choose_key(frames, keys):
    nonce = 0
    for frame in frames:
        if frame.get("error") or frame.get("opcode") != 0 or "body" not in frame:
            continue
        for name, key in keys.items():
            try:
                decrypt_video(key, nonce, frame["header"], frame["body"])
            except ValueError:
                continue
            return name, key
        return None, None
    return None, None


def apply_keys(frames, keys):
    name, key = choose_key(frames, keys)
    if key is None:
        return None
    nonce = 0
    for frame in frames:
        if frame.get("error") or frame.get("opcode") != 0 or "body" not in frame:
            continue
        try:
            plain = decrypt_video(key, nonce, frame["header"], frame["body"])
        except ValueError as exc:
            frame["decryptError"] = str(exc)
            break
        frame["key"] = name
        frame["nonce"] = nonce
        frame["plain"] = plain
        frame["plainBytes"] = len(plain)
        frame["plainPreview"] = plain[:16].hex()
        frame["plainKind"] = describe_plain(plain)
        nonce += 1
    return name


def iter_frames(data: bytes, spans):
    offset = 0
    size = len(data)
    while offset + HEADER_LEN <= size:
        body_size = struct.unpack_from("<I", data, offset)[0]
        opcode = data[offset + 4]
        if body_size > MAX_BODY or opcode > 5:
            yield {
                "offset": offset,
                "time": fmt_ts(ts_at(spans, offset)),
                "error": f"帧头不像屏幕包: opcode={opcode} bodySize={body_size}",
            }
            return
        end = offset + HEADER_LEN + body_size
        if end > size:
            yield {
                "offset": offset,
                "time": fmt_ts(ts_at(spans, offset)),
                "error": f"载荷被截断: 需要 {body_size} 字节，流里还剩 {size - offset - HEADER_LEN}",
            }
            return
        header = data[offset:offset + HEADER_LEN]
        body = data[offset + HEADER_LEN:end]
        info = parse_header(header)
        info["offset"] = offset
        info["time"] = fmt_ts(ts_at(spans, offset))
        if info["opcode"] == 0 and body_size >= 16:
            info["tagBytes"] = 16
            info["cipherBytes"] = body_size - 16
            info["header"] = header
            info["body"] = body
        elif info["opcode"] == 1:
            info["body"] = body
            if len(body) >= 8 and body[4:8] in (b"hvc1", b"avc1"):
                info["codec"] = body[4:8].decode("ascii")
        yield info
        offset = end
    if offset < size:
        yield {
            "offset": offset,
            "time": fmt_ts(ts_at(spans, offset)),
            "error": f"末尾还剩 {size - offset} 字节，不够一个帧头",
        }


def load_flows(path: Path, port: int):
    buckets = {}
    for link, ts, packet in iter_pcap_packets(path.read_bytes()):
        parsed = tcp_payload(packet, link)
        if parsed is None:
            continue
        src, sport, dst, dport, seq, flags, payload = parsed
        if sport != port and dport != port:
            continue
        key = (src, sport, dst, dport)
        slot = buckets.setdefault(key, {"syn": None, "segs": []})
        if flags & 0x02 and slot["syn"] is None:
            slot["syn"] = seq
        if payload:
            slot["segs"].append((seq, payload, ts))

    flows = []
    for (src, sport, dst, dport), slot in buckets.items():
        data, spans = reassemble(slot["segs"], slot["syn"])
        if not data:
            continue
        flows.append({
            "src": f"{src}:{sport}",
            "dst": f"{dst}:{dport}",
            "toScreen": dport == port,
            "bytes": len(data),
            "frames": list(iter_frames(data, spans)) if dport == port else [],
        })
    flows.sort(key=lambda item: (not item["toScreen"], item["src"]))
    return flows


def _extension_payload(body: bytes, fourcc: bytes):
    if len(body) < IMAGE_DESC_LEN + 8 or body[4:8] != fourcc:
        raise ValueError(f"VideoConfig 不是 {fourcc.decode('ascii')} 样本描述")
    atom_size = struct.unpack_from(">I", body, IMAGE_DESC_LEN)[0]
    atom_type = body[IMAGE_DESC_LEN + 4:IMAGE_DESC_LEN + 8]
    start = IMAGE_DESC_LEN + 8
    end = IMAGE_DESC_LEN + atom_size
    if atom_size < 8 or end > len(body):
        raise ValueError(f"扩展 atom 长度异常: {atom_size}")
    return atom_type, body[start:end]


def _hvcc_parameter_sets(hvcc: bytes):
    if len(hvcc) < 23 or hvcc[0] != 1:
        raise ValueError("hvcC 头不够或 configurationVersion 不是 1")
    nal_size = (hvcc[21] & 0x03) + 1
    if nal_size not in (1, 2, 4):
        raise ValueError(f"hvcC 的 NAL 长度字段是 {nal_size} 字节")
    offset = 23
    sets = []
    for _ in range(hvcc[22]):
        if offset + 3 > len(hvcc):
            raise ValueError("hvcC 数组被截断")
        offset += 1
        count = struct.unpack_from(">H", hvcc, offset)[0]
        offset += 2
        for _unit in range(count):
            if offset + 2 > len(hvcc):
                raise ValueError("hvcC 的 NAL 长度被截断")
            length = struct.unpack_from(">H", hvcc, offset)[0]
            offset += 2
            if offset + length > len(hvcc):
                raise ValueError("hvcC 的 NAL 被截断")
            sets.append(hvcc[offset:offset + length])
            offset += length
    if not sets:
        raise ValueError("hvcC 里没有参数集")
    return sets, nal_size


def _avcc_parameter_sets(avcc: bytes):
    if len(avcc) < 7 or avcc[0] != 1:
        raise ValueError("avcC 头不够或 configurationVersion 不是 1")
    nal_size = (avcc[4] & 0x03) + 1
    if nal_size not in (1, 2, 4):
        raise ValueError(f"avcC 的 NAL 长度字段是 {nal_size} 字节")
    offset = 5
    sps_count = avcc[offset] & 0x1F
    offset += 1
    sets = []
    for _ in range(sps_count):
        if offset + 2 > len(avcc):
            raise ValueError("avcC 的 SPS 被截断")
        length = struct.unpack_from(">H", avcc, offset)[0]
        offset += 2
        sets.append(avcc[offset:offset + length])
        offset += length
    if offset >= len(avcc):
        raise ValueError("avcC 没有 PPS 计数")
    pps_count = avcc[offset]
    offset += 1
    for _ in range(pps_count):
        if offset + 2 > len(avcc):
            raise ValueError("avcC 的 PPS 被截断")
        length = struct.unpack_from(">H", avcc, offset)[0]
        offset += 2
        sets.append(avcc[offset:offset + length])
        offset += length
    if not sets:
        raise ValueError("avcC 里没有参数集")
    return sets, nal_size


def parameter_sets(config_body: bytes):
    codec = config_body[4:8]
    atom_type, payload = _extension_payload(config_body, codec)
    if codec == b"hvc1":
        if atom_type != b"hvcC":
            raise ValueError(f"hvc1 后面是 {atom_type!r}，不是 hvcC")
        return _hvcc_parameter_sets(payload)
    if atom_type != b"avcC":
        raise ValueError(f"avc1 后面是 {atom_type!r}，不是 avcC")
    return _avcc_parameter_sets(payload)


def iter_length_nals(plain: bytes, nal_size: int):
    offset = 0
    while offset + nal_size <= len(plain):
        length = int.from_bytes(plain[offset:offset + nal_size], "big")
        offset += nal_size
        if length <= 0 or offset + length > len(plain):
            raise ValueError(f"长度前缀 NAL 越界: 长度={length} 剩余={len(plain) - offset}")
        yield plain[offset:offset + length]
        offset += length
    if offset != len(plain):
        raise ValueError(f"访问单元末尾还剩 {len(plain) - offset} 字节")


def write_annexb(frames, path: Path):
    nal_size = None
    video_count = 0
    param_count = 0
    with path.open("wb") as out:
        for frame in frames:
            if frame.get("error"):
                break
            if frame.get("opcode") == 1 and frame.get("body"):
                sets, nal_size = parameter_sets(frame["body"])
                for nal in sets:
                    out.write(START_CODE + nal)
                param_count += len(sets)
                continue
            if frame.get("opcode") != 0 or "plain" not in frame:
                continue
            if nal_size is None:
                raise ValueError("视频帧前面没有 VideoConfig")
            for nal in iter_length_nals(frame["plain"], nal_size):
                out.write(START_CODE + nal)
            video_count += 1
    return param_count, video_count


def _print_frame(index, frame):
    if frame.get("error"):
        print(f"  #{index} {frame['time']} 偏移 {frame['offset']}: {frame['error']}")
        return
    name = frame["opcodeName"]
    if frame["opcode"] == 0:
        extra = ""
        if frame.get("plainKind"):
            extra = f"  {frame['plainKind']}  {frame['plainPreview']}"
        elif frame.get("decryptError"):
            extra = f"  解密失败: {frame['decryptError']}"
        print(
            f"  #{index} {frame['time']} {name}  "
            f"body={frame['bodySize']} 密文={frame.get('cipherBytes', frame['bodySize'])}  "
            f"pts={frame['pts']}  reencode={frame['reencodeCount']}{extra}"
        )
    elif frame["opcode"] == 1:
        flags = ",".join(frame["flagNames"]) or "0"
        print(
            f"  #{index} {frame['time']} {name}  "
            f"{frame['width']:.0f}x{frame['height']:.0f}  "
            f"view=({frame['viewAreaOriginX']:.0f},{frame['viewAreaOriginY']:.0f}) "
            f"{frame['viewAreaWidth']:.0f}x{frame['viewAreaHeight']:.0f}  "
            f"flags={flags}  body={frame['bodySize']}"
            + (f"  codec={frame['codec']}" if frame.get("codec") else "")
        )
    else:
        print(f"  #{index} {frame['time']} {name}  body={frame['bodySize']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="解析 MainScreen TCP 视频帧头")
    parser.add_argument("pcap", help="含 dataPort 流量的 pcap，原始包即可")
    parser.add_argument("--port", type=int, default=51077, help="SETUP 回复里的 dataPort，默认 51077")
    parser.add_argument("--keys", default="all_carplay_pair_verify_keys.txt", help="含 stream_*_output 的密钥文件")
    parser.add_argument("-o", "--output", help="把帧头写成 JSON 文件")
    parser.add_argument("--annexb", help="把参数集和视频帧写成 Annex-B 基本流，HEVC 用 .h265")
    args = parser.parse_args()

    keys = {}
    key_path = Path(args.keys)
    if key_path.is_file():
        try:
            keys = load_output_keys(key_path)
        except Exception as exc:
            print(f"读取密钥失败: {exc}", file=sys.stderr)
            return 1
    else:
        print(f"未找到密钥文件 {key_path}，只解析帧头", file=sys.stderr)

    try:
        flows = load_flows(Path(args.pcap), args.port)
    except Exception as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    screen_flows = [item for item in flows if item["toScreen"]]
    if not screen_flows:
        print(f"没有找到发往端口 {args.port} 的 TCP 载荷")
        return 0

    for flow in screen_flows:
        frames = flow["frames"]
        counts = {}
        for frame in frames:
            counts[frame.get("opcodeName", "error")] = counts.get(frame.get("opcodeName", "error"), 0) + 1
        used = apply_keys(frames, keys) if keys else None
        print(f"======== {flow['src']} -> {flow['dst']}  {flow['bytes']} 字节 ========")
        if used:
            print(f"VideoFrame 已用 {used} 解密，明文是长度前缀码流")
        elif keys:
            print("密钥文件里的 stream_*_output 都没有对上这条流")
        else:
            print("没有密钥，VideoFrame 载荷仍是密文")
        print("计数: " + ", ".join(f"{name}={count}" for name, count in counts.items()))
        for index, frame in enumerate(frames, 1):
            _print_frame(index, frame)
        print()
        if args.annexb:
            if not used:
                print("没有解开 VideoFrame，不能写 Annex-B", file=sys.stderr)
                return 1
            try:
                params, videos = write_annexb(frames, Path(args.annexb))
            except ValueError as exc:
                print(f"写 Annex-B 失败: {exc}", file=sys.stderr)
                return 1
            print(f"已写入 {args.annexb}  参数集={params}  视频帧={videos}")
            print(f"播放: ffplay -f hevc {args.annexb}")

    if args.output:
        for flow in screen_flows:
            for frame in flow["frames"]:
                frame.pop("header", None)
                frame.pop("body", None)
                frame.pop("plain", None)
        Path(args.output).write_text(json.dumps(screen_flows, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写入 {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
