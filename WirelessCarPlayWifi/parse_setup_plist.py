#!/usr/bin/env python3
"""Decode an AirPlay SETUP response body (Apple binary plist).

Accepts either:
  - a raw plist export (Wireshark: Data field -> Export Packet Bytes)
  - a full RTSP response that still contains the headers; the bplist00 body is sliced out

Usage:
  python parse_setup_plist.py setup-body.bin
  python parse_setup_plist.py setup-reply.bin --json
"""

from __future__ import annotations

import argparse
import base64
import json
import plistlib
import sys
from datetime import datetime
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

KEY_NOTES = {
    "timingPort": "时钟同步端口",
    "eventPort": "事件连接端口，车机在这条连接上发 POST /command",
    "keepAlivePort": "低功耗保活端口",
    "enabledFeatures": "车机打开的能力",
    "streams": "本次 SETUP 带回的流",
    "type": "流类型，见 kAirPlayStreamType_*",
    "dataPort": "这条流的数据端口",
    "streamID": "数据流 ID",
    "timestamp": "高精度主机时间戳",
    "sampleTime": "采样时间",
    "timestampRawNs": "原始主机时间，纳秒",
}


def extract_plist(blob: bytes) -> bytes:
    marker = b"bplist00"
    at = blob.find(marker)
    if at >= 0:
        return blob[at:]
    stripped = blob.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<plist"):
        return stripped
    raise ValueError("文件里没有 bplist00，也不是 XML plist。请导出 SETUP 响应的 Data，或整段 RTSP 响应。")


def to_plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_plain(v) for v in value]
    if isinstance(value, tuple):
        return [to_plain(v) for v in value]
    if isinstance(value, bytes):
        return {"_bytes": len(value), "hex": value.hex(), "b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def annotate_stream_type(node: Any) -> None:
    if isinstance(node, dict):
        stream_type = node.get("type")
        if isinstance(stream_type, int) and stream_type in STREAM_TYPES:
            node["typeName"] = STREAM_TYPES[stream_type]
        for value in node.values():
            annotate_stream_type(value)
    elif isinstance(node, list):
        for item in node:
            annotate_stream_type(item)


def print_summary(data: dict) -> None:
    print("---- SETUP 响应摘要 ----")
    for key in ("timingPort", "eventPort", "keepAlivePort"):
        if key in data:
            note = KEY_NOTES.get(key, "")
            print(f"  {key}: {data[key]}    {note}")
    features = data.get("enabledFeatures")
    if isinstance(features, list):
        print(f"  enabledFeatures ({len(features)}):")
        for item in features:
            print(f"    - {item}")
    streams = data.get("streams")
    if isinstance(streams, list):
        print(f"  streams ({len(streams)}):")
        for index, stream in enumerate(streams):
            if not isinstance(stream, dict):
                print(f"    [{index}] {stream}")
                continue
            type_id = stream.get("type")
            type_name = STREAM_TYPES.get(type_id, "?") if isinstance(type_id, int) else "?"
            extra = []
            for field in ("dataPort", "streamID", "timestamp", "sampleTime", "timestampRawNs"):
                if field in stream:
                    extra.append(f"{field}={stream[field]}")
            tail = ", ".join(extra)
            print(f"    [{index}] type={type_id} ({type_name})" + (f"  {tail}" if tail else ""))
    other = [key for key in data.keys() if key not in {"timingPort", "eventPort", "keepAlivePort", "enabledFeatures", "streams"}]
    if other:
        print("  其他键: " + ", ".join(other))
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="解析 AirPlay SETUP 响应里的 binary plist")
    parser.add_argument("path", help="setup-body.bin，或含 RTSP 头的整段响应")
    parser.add_argument("--json", action="store_true", help="只打印 JSON，不打印摘要")
    args = parser.parse_args()

    blob = open(args.path, "rb").read()
    try:
        plist_bytes = extract_plist(blob)
        data = plistlib.loads(plist_bytes)
    except Exception as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    plain = to_plain(data)
    if isinstance(plain, dict):
        annotate_stream_type(plain)

    if not args.json and isinstance(plain, dict):
        print_summary(plain)

    print("---- plist ----")
    json.dump(plain, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
