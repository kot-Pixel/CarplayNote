#!/usr/bin/env python3
"""从解密后的 pcap 里抽出 SETUP 请求和对应 Reply，并解开 body 里的 binary plist。

SETUP 的请求行、状态行、CSeq 是 RTSP 文本。Content-Type 为
application/x-apple-binary-plist 时，空行后面的 body 才是 plist。

用法:
  python parse_setup_pcap.py carplay_7000_decrypted.pcap
  python parse_setup_pcap.py carplay_7000_decrypted.pcap -o setup_pairs.json
"""

from __future__ import annotations

import argparse
import base64
import json
import plistlib
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


STREAM_TYPES = {
    100: "MainAudio",
    101: "AltAudio",
    102: "MainHighAudio",
    103: "BufferedAudio",
    104: "MainAudioWithRedundancy",
    105: "AltAudioWithRedundancy",
    106: "AuxOutAudio",
    107: "AuxInAudio",
    108: "AuxOutAudioWithRedundancy",
    109: "AuxInAudioWithRedundancy",
    110: "MainScreen",
    111: "AltScreen",
    130: "DataStream",
}


def iter_pcap_packets(blob: bytes):
    if len(blob) < 24:
        raise ValueError("pcap 太短")
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise ValueError(f"不是经典 pcap（magic={magic:#x}）")
    link = struct.unpack_from(endian + "I", blob, 20)[0]
    off = 24
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, _orig = struct.unpack_from(endian + "IIII", blob, off)
        off += 16
        if off + incl > len(blob):
            break
        yield link, (ts_sec, ts_usec), blob[off:off + incl]
        off += incl


def tcp_payload(packet: bytes, link: int):
    if link == 113:
        if len(packet) < 16:
            return None
        ethertype = struct.unpack_from("!H", packet, 14)[0]
        frame = packet[16:]
    elif link == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        frame = packet[14:]
    else:
        raise ValueError(f"不支持的链路类型 {link}")

    if ethertype == 0x8100 and len(frame) >= 4:
        ethertype = struct.unpack_from("!H", frame, 2)[0]
        frame = frame[4:]

    if ethertype == 0x0800:
        if len(frame) < 20:
            return None
        ihl = (frame[0] & 0x0F) * 4
        if frame[9] != 6 or len(frame) < ihl + 20:
            return None
        src_raw, dst_raw = frame[12:16], frame[16:20]
        src = ".".join(str(b) for b in src_raw)
        dst = ".".join(str(b) for b in dst_raw)
        tcp = frame[ihl:]
    elif ethertype == 0x86DD:
        if len(frame) < 40 or frame[6] != 6:
            return None
        src_raw, dst_raw = frame[8:24], frame[24:40]
        src = ":".join(f"{struct.unpack_from('!H', src_raw, i)[0]:x}" for i in range(0, 16, 2))
        dst = ":".join(f"{struct.unpack_from('!H', dst_raw, i)[0]:x}" for i in range(0, 16, 2))
        tcp = frame[40:]
    else:
        return None

    sport, dport, seq = struct.unpack_from("!HHI", tcp, 0)
    flags = tcp[13]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:] if doff <= len(tcp) else b""
    return src, sport, dst, dport, seq, flags, payload


def reassemble(segments, syn_seq):
    payloads = [(seq, data, ts) for seq, data, ts in segments if data]
    if not payloads:
        return b"", []
    start = (syn_seq + 1) & 0xFFFFFFFF if syn_seq is not None else min(seq for seq, _, _ in payloads)

    def dist(seq):
        return (seq - start) & 0xFFFFFFFF

    end = max(dist(seq) + len(data) for seq, data, _ in payloads)
    buf = bytearray(end)
    seen = bytearray(end)
    spans = []
    for seq, data, ts in payloads:
        off = dist(seq)
        buf[off:off + len(data)] = data
        seen[off:off + len(data)] = b"\x01" * len(data)
        spans.append((off, off + len(data), ts))
    contiguous = 0
    while contiguous < end and seen[contiguous]:
        contiguous += 1
    return bytes(buf[:contiguous]), spans


def ts_at(spans, offset):
    found = None
    for start, end, ts in spans:
        if start <= offset < end:
            found = ts
    if found:
        return found
    return spans[0][2] if spans else (0, 0)


def split_rtsp(data: bytes):
    messages = []
    index = 0
    size = len(data)
    while index < size:
        end = data.find(b"\r\n\r\n", index)
        if end < 0:
            rest = data[index:]
            if rest.strip(b"\x00"):
                messages.append((index, rest))
            break
        length = 0
        for line in data[index:end].split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip() or b"0")
                except ValueError:
                    length = 0
                break
        body_end = end + 4 + length
        if body_end > size:
            messages.append((index, data[index:]))
            break
        messages.append((index, data[index:body_end]))
        index = body_end
    return messages


def parse_message(raw: bytes):
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        body = b""
    lines = head.split(b"\r\n")
    start = lines[0].decode("latin1", errors="replace").strip()
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("latin1").strip().lower()] = value.decode("latin1").strip()
    is_response = start.upper().startswith("RTSP/") or start.upper().startswith("HTTP/")
    method = uri = status = None
    if is_response:
        parts = start.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    else:
        parts = start.split(" ")
        if parts:
            method = parts[0].upper()
        if len(parts) >= 2:
            uri = parts[1]
    cseq = None
    if "cseq" in headers:
        try:
            cseq = int(headers["cseq"])
        except ValueError:
            cseq = None
    return {
        "start": start,
        "method": method,
        "uri": uri,
        "status": status,
        "cseq": cseq,
        "headers": headers,
        "body": body if sep else b"",
        "response": is_response,
    }


def to_plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
        if value and all(32 <= b < 127 or b in (9, 10, 13) for b in value):
            return text
        return {"_bytes": len(value), "hex": value.hex(), "b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def annotate(node: Any) -> None:
    if isinstance(node, dict):
        stream_type = node.get("type")
        if isinstance(stream_type, int) and stream_type in STREAM_TYPES and "typeName" not in node:
            node["typeName"] = STREAM_TYPES[stream_type]
        for value in node.values():
            annotate(value)
    elif isinstance(node, list):
        for item in node:
            annotate(item)


def parse_body(body: bytes, content_type: str):
    if not body:
        return None, "空 body"
    blob = body
    at = blob.find(b"bplist00")
    if at >= 0:
        blob = blob[at:]
    elif not (content_type and "plist" in content_type.lower()):
        return None, f"不是 plist（Content-Type={content_type or '无'}，{len(body)} 字节）"
    try:
        plain = to_plain(plistlib.loads(blob))
    except Exception as exc:
        return None, f"plist 解析失败: {exc}"
    if isinstance(plain, dict):
        annotate(plain)
    return plain, None


def fmt_ts(ts):
    sec, usec = ts
    if usec >= 1_000_000:
        sec += usec // 1_000_000
        usec %= 1_000_000
    return datetime.fromtimestamp(sec + usec / 1_000_000).isoformat(timespec="milliseconds")


def load_messages(path: Path):
    blob = path.read_bytes()
    buckets = {}
    for link, ts, packet in iter_pcap_packets(blob):
        parsed = tcp_payload(packet, link)
        if parsed is None:
            continue
        src, sport, dst, dport, seq, flags, payload = parsed
        key = (src, sport, dst, dport)
        slot = buckets.setdefault(key, {"syn": None, "segs": []})
        if flags & 0x02 and slot["syn"] is None:
            slot["syn"] = seq
        if payload:
            slot["segs"].append((seq, payload, ts))

    directions = []
    for (src, sport, dst, dport), slot in buckets.items():
        data, spans = reassemble(slot["segs"], slot["syn"])
        messages = []
        for offset, raw in split_rtsp(data):
            msg = parse_message(raw)
            msg["time"] = fmt_ts(ts_at(spans, offset))
            msg["src"] = f"{src}:{sport}"
            msg["dst"] = f"{dst}:{dport}"
            messages.append(msg)
        directions.append({
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "messages": messages,
        })
    return directions


def pair_setups(directions):
    by_conn = {}
    for direction in directions:
        ends = tuple(sorted([(direction["src"], direction["sport"]), (direction["dst"], direction["dport"])]))
        by_conn.setdefault(ends, []).extend(direction["messages"])

    pairs = []
    for ends, messages in by_conn.items():
        messages.sort(key=lambda item: item["time"])
        replies = {}
        for msg in messages:
            if msg["response"] and msg["cseq"] is not None:
                replies.setdefault(msg["cseq"], []).append(msg)
        for msg in messages:
            if msg["response"] or msg["method"] != "SETUP":
                continue
            reply = None
            if msg["cseq"] is not None and replies.get(msg["cseq"]):
                reply = replies[msg["cseq"]].pop(0)
            req_plist, req_err = parse_body(msg["body"], msg["headers"].get("content-type", ""))
            rep_plist, rep_err = (None, None)
            if reply:
                rep_plist, rep_err = parse_body(reply["body"], reply["headers"].get("content-type", ""))
            pairs.append({
                "connection": [f"{a}:{b}" for a, b in ends],
                "time": msg["time"],
                "cseq": msg["cseq"],
                "request": msg["start"],
                "requestFrom": f"{msg['src']} -> {msg['dst']}",
                "requestError": req_err,
                "requestPlist": req_plist,
                "reply": reply["start"] if reply else None,
                "replyTime": reply["time"] if reply else None,
                "replyError": rep_err,
                "replyPlist": rep_plist,
            })
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(description="从解密 pcap 解析 SETUP / Reply 的 plist")
    parser.add_argument("pcap", help="解密后的 pcap，例如 carplay_7000_decrypted.pcap")
    parser.add_argument("-o", "--output", help="把配对结果写成 JSON 文件")
    args = parser.parse_args()

    path = Path(args.pcap)
    try:
        pairs = pair_setups(load_messages(path))
    except Exception as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    if not pairs:
        print("没有找到 SETUP")
        return 0

    print(f"共 {len(pairs)} 条 SETUP\n")
    for index, pair in enumerate(pairs, 1):
        print(f"======== SETUP #{index}  CSeq={pair['cseq']}  {pair['time']} ========")
        print(pair["requestFrom"])
        print(pair["request"])
        if pair["requestError"]:
            print("请求 body:", pair["requestError"])
        else:
            print("请求 plist:")
            print(json.dumps(pair["requestPlist"], ensure_ascii=False, indent=2))
        if pair["reply"]:
            print(f"Reply {pair['replyTime']}: {pair['reply']}")
            if pair["replyError"]:
                print("响应 body:", pair["replyError"])
            else:
                print("响应 plist:")
                print(json.dumps(pair["replyPlist"], ensure_ascii=False, indent=2))
        else:
            print("没有配到 Reply")
        print()

    if args.output:
        Path(args.output).write_text(json.dumps(pairs, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写入 {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
