#!/usr/bin/env python3
"""从解密后的 pcap 里抽出 RECORD 请求和对应 Reply。

车机在 _requestProcessRecord 里读的是请求头 X-Apple-Durations，
分号分隔的 name=毫秒。body 通常为空，响应一般也没有 plist。

每条 RECORD 打完请求行后立刻打印耗时和 body，再打印 Reply。

用法:
  python parse_record_pcap.py carplay_7000_decrypted.pcap
  python parse_record_pcap.py carplay_7000_decrypted.pcap -o record_pairs.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from parse_setup_pcap import load_messages, parse_body


# AirPlayReceiverServer.c _requestProcessRecord
DURATION_NAMES = {
    "b": "bonjourMs",
    "c": "connectMs",
    "au": "authMs",
    "an": "announceMs",
    "sa": "setupAudioMs",
    "ss": "setupScreenMs",
}


def parse_durations(value: str):
    if not value:
        return None
    items = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, raw = part.partition("=")
        name = name.strip()
        raw = raw.strip() if sep else ""
        item = {
            "name": name,
            "field": DURATION_NAMES.get(name, name),
        }
        if raw.lstrip("-").isdigit():
            item["ms"] = int(raw)
        elif raw:
            item["value"] = raw
        items.append(item)
    return items


def pair_records(directions):
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
            if msg["response"] or msg["method"] != "RECORD":
                continue
            reply = None
            if msg["cseq"] is not None and replies.get(msg["cseq"]):
                reply = replies[msg["cseq"]].pop(0)
            durations_raw = msg["headers"].get("x-apple-durations", "")
            req_plist, req_err = parse_body(msg["body"], msg["headers"].get("content-type", ""))
            rep_plist, rep_err = (None, None)
            reply_type = ""
            if reply:
                reply_type = reply["headers"].get("content-type", "")
                rep_plist, rep_err = parse_body(reply["body"], reply_type)
            pairs.append({
                "connection": [f"{a}:{b}" for a, b in ends],
                "time": msg["time"],
                "cseq": msg["cseq"],
                "request": msg["start"],
                "requestFrom": f"{msg['src']} -> {msg['dst']}",
                "durationsRaw": durations_raw or None,
                "durations": parse_durations(durations_raw),
                "requestError": req_err,
                "requestPlist": req_plist,
                "reply": reply["start"] if reply else None,
                "replyTime": reply["time"] if reply else None,
                "replyType": reply_type,
                "replyError": rep_err,
                "replyPlist": rep_plist,
            })
    return pairs


def _print_body(label, plist, error):
    if error == "空 body":
        print(f"{label}: 无 body")
        return
    if error:
        print(f"{label}: {error}")
        return
    print(f"{label} plist:")
    print(json.dumps(plist, ensure_ascii=False, indent=2))


def _print_durations(pair):
    if not pair["durations"]:
        print("X-Apple-Durations: 无")
        return
    print(f"X-Apple-Durations: {pair['durationsRaw']}")
    for item in pair["durations"]:
        shown = item.get("ms", item.get("value", ""))
        unit = " ms" if "ms" in item else ""
        print(f"  {item['name']} = {shown}{unit}    {item['field']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="从解密 pcap 解析 RECORD / Reply")
    parser.add_argument("pcap", help="解密后的 pcap，例如 carplay_7000_decrypted.pcap")
    parser.add_argument("-o", "--output", help="把配对结果写成 JSON 文件")
    args = parser.parse_args()

    try:
        pairs = pair_records(load_messages(Path(args.pcap)))
    except Exception as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    if not pairs:
        print("没有找到 RECORD")
        return 0

    print(f"共 {len(pairs)} 条 RECORD\n")
    for index, pair in enumerate(pairs, 1):
        print(f"======== RECORD #{index}  CSeq={pair['cseq']}  {pair['time']} ========")
        print(pair["requestFrom"])
        print(pair["request"])
        _print_durations(pair)
        _print_body("请求", pair["requestPlist"], pair["requestError"])
        if pair["reply"]:
            print(f"Reply {pair['replyTime']}: {pair['reply']}")
            if pair["replyType"]:
                print(f"Content-Type: {pair['replyType']}")
            _print_body("响应", pair["replyPlist"], pair["replyError"])
        else:
            print("没有配到 Reply")
        print()

    if args.output:
        Path(args.output).write_text(json.dumps(pairs, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写入 {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
