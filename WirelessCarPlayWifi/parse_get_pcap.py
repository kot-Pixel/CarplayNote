#!/usr/bin/env python3
"""从解密后的 pcap 里抽出 GET 请求和对应 Reply，并解开 body 里的 binary plist。

协议栈里的 GET 主要是 GET /info 和 GET /logs。请求往往没有 body，
车机的响应体才是 application/x-apple-binary-plist。

每条 GET 打完请求行后立刻打印它的 plist，再打印 Reply 和响应 plist。

用法:
  python parse_get_pcap.py carplay_7000_decrypted.pcap
  python parse_get_pcap.py carplay_7000_decrypted.pcap -o get_pairs.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from parse_setup_pcap import load_messages, parse_body


def pair_gets(directions):
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
            if msg["response"] or msg["method"] != "GET":
                continue
            reply = None
            if msg["cseq"] is not None and replies.get(msg["cseq"]):
                reply = replies[msg["cseq"]].pop(0)
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
                "path": msg["uri"],
                "requestFrom": f"{msg['src']} -> {msg['dst']}",
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


def main() -> int:
    parser = argparse.ArgumentParser(description="从解密 pcap 解析 GET / Reply 的 plist")
    parser.add_argument("pcap", help="解密后的 pcap，例如 carplay_7000_decrypted.pcap")
    parser.add_argument("-o", "--output", help="把配对结果写成 JSON 文件")
    args = parser.parse_args()

    try:
        pairs = pair_gets(load_messages(Path(args.pcap)))
    except Exception as exc:
        print(f"解析失败: {exc}", file=sys.stderr)
        return 1

    if not pairs:
        print("没有找到 GET")
        return 0

    print(f"共 {len(pairs)} 条 GET\n")
    for index, pair in enumerate(pairs, 1):
        print(f"======== GET #{index}  CSeq={pair['cseq']}  {pair['time']} ========")
        print(pair["requestFrom"])
        print(pair["request"])
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
