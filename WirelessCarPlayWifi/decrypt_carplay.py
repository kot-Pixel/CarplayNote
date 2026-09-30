# CarPlay port-7000 control-channel decryptor.
# ChaCha20-Poly1305 with an 8-byte nonce (64-bit counter), RFC 7539 Poly1305 layout.

import argparse
import struct
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = _rotl(s[b], 7)


def _chacha_block(key, nonce, counter):
    const = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    k = struct.unpack("<8I", key)
    st = list(const + k + (
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        *struct.unpack("<2I", nonce),
    ))
    w = st[:]
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12)
        _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14)
        _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15)
        _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13)
        _quarter(w, 3, 4, 9, 14)
    return b"".join(struct.pack("<I", (w[i] + st[i]) & 0xFFFFFFFF) for i in range(16))


def _poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    prime = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = (acc + int.from_bytes(block + b"\x01", "little")) * r % prime
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(data):
    n = len(data) % 16
    return data if n == 0 else data + b"\x00" * (16 - n)


def aead_open(key, nonce, aad, ciphertext, tag):
    otk = _chacha_block(key, nonce, 0)[:32]
    mac_input = _pad16(aad) + _pad16(ciphertext) + struct.pack("<QQ", len(aad), len(ciphertext))
    if _poly1305(mac_input, otk) != tag:
        raise ValueError("tag")
    plain = bytearray(ciphertext)
    offset = 0
    counter = 1
    while offset < len(plain):
        block = _chacha_block(key, nonce, counter)
        take = min(64, len(plain) - offset)
        for i in range(take):
            plain[offset + i] ^= block[i]
        offset += take
        counter += 1
    return bytes(plain)


def load_keys(path):
    keys = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        raw = bytes.fromhex(value.strip())
        if len(raw) != 32:
            raise ValueError(f"{name} 不是 32 字节")
        keys[name.strip()] = raw
    for name in ("control_write", "control_read"):
        if name not in keys:
            raise ValueError(f"密钥文件缺少 {name}")
    return keys


def iter_pcap_packets(blob):
    if len(blob) < 24:
        raise ValueError("pcap 太短")
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise ValueError(f"不是经典 pcap（magic={magic:#x}）。请用 tcpdump -w 保存。")
    link = struct.unpack_from(endian + "I", blob, 20)[0]
    off = 24
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII", blob, off)
        off += 16
        if off + incl > len(blob):
            break
        yield link, (ts_sec, ts_usec), blob[off:off + incl]
        off += incl


def _tcp_payload(packet, link):
    if link == 113:  # Linux cooked
        if len(packet) < 16:
            return None
        ethertype = struct.unpack_from("!H", packet, 14)[0]
        frame = packet[16:]
    elif link == 1:  # Ethernet
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
        src_raw = frame[12:16]
        dst_raw = frame[16:20]
        src = ".".join(str(b) for b in src_raw)
        dst = ".".join(str(b) for b in dst_raw)
        tcp = frame[ihl:]
    elif ethertype == 0x86DD:
        if len(frame) < 40:
            return None
        nh = frame[6]
        hdr = 40
        while nh in (0, 43, 44, 60) and hdr + 8 <= len(frame):
            nh = frame[hdr]
            hdr += 8 if nh == 44 else (frame[hdr + 1] + 1) * 8
        if nh != 6 or len(frame) < hdr + 20:
            return None
        src_raw = frame[8:24]
        dst_raw = frame[24:40]
        src = ":".join(f"{struct.unpack_from('!H', src_raw, i)[0]:x}" for i in range(0, 16, 2))
        dst = ":".join(f"{struct.unpack_from('!H', dst_raw, i)[0]:x}" for i in range(0, 16, 2))
        tcp = frame[hdr:]
    else:
        return None

    sport, dport, seq = struct.unpack_from("!HHI", tcp, 0)
    flags = tcp[13]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:] if doff <= len(tcp) else b""
    return src, src_raw, sport, dst, dst_raw, dport, seq, flags, payload


def reassemble(segments, syn_seq):
    payloads = [(seq, data, ts) for seq, data, ts in segments if data]
    if not payloads and syn_seq is None:
        return b"", None, []
    start = (syn_seq + 1) & 0xFFFFFFFF if syn_seq is not None else min(seq for seq, _, _ in payloads)
    if not payloads:
        return b"", None, []

    def dist(seq):
        return (seq - start) & 0xFFFFFFFF

    end = max(dist(seq) + len(data) for seq, data, _ in payloads)
    if end > 8 * 1024 * 1024:
        raise ValueError("流太大")
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
    gap = contiguous < end
    return bytes(buf[:contiguous]), gap, spans


def flows_from_pcap(blob, port=7000):
    buckets = {}
    link_type = None
    for link, ts, packet in iter_pcap_packets(blob):
        link_type = link
        parsed = _tcp_payload(packet, link)
        if parsed is None:
            continue
        src, src_raw, sport, dst, dst_raw, dport, seq, flags, payload = parsed
        if sport != port and dport != port:
            continue
        key = (src, sport, dst, dport)
        slot = buckets.setdefault(key, {
            "syn": None, "syn_ts": None, "segs": [], "src_raw": src_raw, "dst_raw": dst_raw,
        })
        if flags & 0x02 and slot["syn"] is None:
            slot["syn"] = seq
            slot["syn_ts"] = ts
        if payload:
            slot["segs"].append((seq, payload, ts))

    flows = []
    for (src, sport, dst, dport), slot in buckets.items():
        data, gap, spans = reassemble(slot["segs"], slot["syn"])
        flows.append({
            "src": src,
            "src_raw": slot["src_raw"],
            "sport": sport,
            "dst": dst,
            "dst_raw": slot["dst_raw"],
            "dport": dport,
            "data": data,
            "gap": gap,
            "spans": spans,
            "syn_ts": slot["syn_ts"],
            "to_car": dport == port,
        })
    return flows, link_type


def decrypt_stream(blob, key, max_frame=16 * 1024):
    def one(off, n):
        if off + 2 > len(blob):
            raise ValueError("short")
        length = struct.unpack_from("<H", blob, off)[0]
        if length > max_frame or off + 2 + length + 16 > len(blob):
            raise ValueError("len")
        aad = blob[off:off + 2]
        ct = blob[off + 2:off + 2 + length]
        tag = blob[off + 2 + length:off + 18 + length]
        nonce = n.to_bytes(8, "little")
        return aead_open(key, nonce, aad, ct, tag), off + 18 + length

    start = None
    for off in range(len(blob)):
        try:
            _, nxt = one(off, 0)
            if nxt < len(blob):
                one(nxt, 1)
            start = off
            break
        except ValueError:
            continue
    if start is None:
        raise ValueError("没有对上的加密帧")

    out = bytearray()
    off = start
    n = 0
    frames_at = []
    while off + 18 <= len(blob):
        try:
            pt, nxt = one(off, n)
        except ValueError:
            break
        frames_at.append((len(out), off))
        out += pt
        off = nxt
        n += 1
    return bytes(out), start, n, off, frames_at


def _preview(data):
    if not data:
        return "(空)"
    text = data.decode("utf-8", errors="replace")
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if printable < len(data) * 0.6:
        hex_part = data[:256].hex()
        return text + "\n\n--- 前 256 字节 hex ---\n" + hex_part
    return text


def decrypt_pcap(pcap_path, keys_path, port=7000):
    keys = load_keys(keys_path)
    blob = Path(pcap_path).read_bytes()
    flows, link = flows_from_pcap(blob, port)
    if not flows:
        raise ValueError(f"pcap 里没有 TCP {port} 的数据（链路类型 {link}）")

    # Merge directions. A second connection on 7000 is reported separately.
    groups = {}
    for flow in flows:
        pair = tuple(sorted([(flow["src"], flow["sport"]), (flow["dst"], flow["dport"])]))
        groups.setdefault(pair, []).append(flow)

    reports = []
    for pair, sides in groups.items():
        report = {"pair": pair, "sides": []}
        for flow in sides:
            direction = "phone->car" if flow["to_car"] else "car->phone"
            key_name = "control_write" if flow["to_car"] else "control_read"
            alt_name = "events_read" if flow["to_car"] else "events_write"
            used = key_name
            try:
                plain, skip, frames, consumed, frames_at = decrypt_stream(flow["data"], keys[key_name])
            except ValueError:
                if alt_name in keys:
                    plain, skip, frames, consumed, frames_at = decrypt_stream(flow["data"], keys[alt_name])
                    used = alt_name
                else:
                    raise
            prefix = flow["data"][:skip]
            report["sides"].append({
                "direction": direction,
                "key": used,
                "src": f"{flow['src']}:{flow['sport']}",
                "dst": f"{flow['dst']}:{flow['dport']}",
                "src_raw": flow["src_raw"],
                "dst_raw": flow["dst_raw"],
                "sport": flow["sport"],
                "dport": flow["dport"],
                "gap": flow["gap"],
                "skip": skip,
                "frames": frames,
                "frames_at": frames_at,
                "spans": flow["spans"],
                "syn_ts": flow["syn_ts"],
                "consumed": consumed,
                "total": len(flow["data"]),
                "prefix": prefix,
                "plain": plain,
                "stream": prefix + plain,
            })
        reports.append(report)
    return reports


def format_report(reports):
    chunks = []
    for report in reports:
        for side in report["sides"]:
            header = (
                f"===== {side['direction']}  {side['src']} -> {side['dst']} =====\n"
                f"key={side['key']}  skip={side['skip']}  frames={side['frames']}  "
                f"plain={len(side['plain'])}  stream={side['total']}"
            )
            if side["gap"]:
                header += "  (TCP 流中间有缺口，后面的字节没有拼上)"
            if side["consumed"] < side["total"]:
                header += f"  (解密停在 {side['consumed']}/{side['total']})"
            body = []
            if side["prefix"]:
                body.append("--- pair-verify 明文 ---\n" + _preview(side["prefix"]))
            body.append("--- 解密后 ---\n" + _preview(side["plain"]))
            chunks.append(header + "\n" + "\n".join(body))
    return "\n\n".join(chunks) + "\n"


def _inet_checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_segment(src_raw, dst_raw, sport, dport, seq, ack, flags, payload):
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, 0, 0) + payload
    if len(src_raw) == 16:
        pseudo = src_raw + dst_raw + struct.pack("!I3xB", len(tcp), 6)
        csum = _inet_checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
        ip = struct.pack("!IHBB", 0x60000000, len(tcp), 6, 64) + src_raw + dst_raw
        ethertype = 0x86DD
    else:
        ip_len = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0, src_raw, dst_raw)
        ip = ip[:10] + struct.pack("!H", _inet_checksum(ip)) + ip[12:]
        pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, 6, len(tcp))
        csum = _inet_checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
        ethertype = 0x0800
    sll = struct.pack("!HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack("!H", ethertype)
    return sll + ip + tcp


def _split_rtsp(data):
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


def _cseq(message):
    head = message.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"cseq:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return None
    return None


def _emit_message(src_raw, dst_raw, sport, dport, seq, ack, message):
    packets = []
    offset = 0
    limit = 60000
    while offset < len(message):
        piece = message[offset:offset + limit]
        packets.append(_tcp_segment(src_raw, dst_raw, sport, dport, seq, ack, 0x18, piece))
        seq = (seq + len(piece)) & 0xFFFFFFFF
        offset += len(piece)
    return packets, seq


def _ts_at(spans, offset):
    found = None
    prev = None
    for start, end, ts in spans:
        if start <= offset:
            prev = ts
        if start <= offset < end:
            found = ts
    if found:
        return found
    if prev:
        return prev
    return spans[0][2] if spans else (0, 0)


def _cipher_off(stream_off, skip, frames_at):
    if stream_off < skip or not frames_at:
        return stream_off
    plain_off = stream_off - skip
    cipher = frames_at[0][1]
    for plain_at, cipher_at in frames_at:
        if plain_at <= plain_off:
            cipher = cipher_at
        else:
            break
    return cipher


def _message_ts(side, stream_off):
    cipher = _cipher_off(stream_off, side["skip"], side["frames_at"])
    return _ts_at(side["spans"], cipher)


def _endpoint_ts(side, which):
    spans = side["spans"]
    syn = side["syn_ts"]
    first = spans[0][2] if spans else (0, 0)
    last = spans[-1][2] if spans else first
    if which == "first":
        return syn or first
    return last or syn or first


def write_decrypted_pcap(reports, out_path):
    frames = []
    order = 0
    for report in reports:
        sides = report["sides"]
        if not sides:
            continue
        client = next((s for s in sides if s["direction"] == "phone->car"), sides[0])
        server = next((s for s in sides if s["direction"] == "car->phone"), None)
        events = []

        def add(ts, rank, src_raw, dst_raw, sport, dport, flags, payload):
            nonlocal order
            events.append((ts[0], ts[1], rank, order, src_raw, dst_raw, sport, dport, flags, payload))
            order += 1

        add(_endpoint_ts(client, "first"), 0,
            client["src_raw"], client["dst_raw"], client["sport"], client["dport"], 0x02, b"")
        if server:
            add(_endpoint_ts(server, "first"), 1,
                server["src_raw"], server["dst_raw"], server["sport"], server["dport"], 0x12, b"")
            add(_endpoint_ts(client, "first"), 2,
                client["src_raw"], client["dst_raw"], client["sport"], client["dport"], 0x10, b"")
            for stream_off, message in _split_rtsp(client["stream"]):
                add(_message_ts(client, stream_off), 3,
                    client["src_raw"], client["dst_raw"], client["sport"], client["dport"], 0x18, message)
            for stream_off, message in _split_rtsp(server["stream"]):
                add(_message_ts(server, stream_off), 3,
                    server["src_raw"], server["dst_raw"], server["sport"], server["dport"], 0x18, message)
            add(_endpoint_ts(client, "last"), 4,
                client["src_raw"], client["dst_raw"], client["sport"], client["dport"], 0x11, b"")
            add(_endpoint_ts(server, "last"), 4,
                server["src_raw"], server["dst_raw"], server["sport"], server["dport"], 0x11, b"")
        else:
            for stream_off, message in _split_rtsp(client["stream"]):
                add(_message_ts(client, stream_off), 3,
                    client["src_raw"], client["dst_raw"], client["sport"], client["dport"], 0x18, message)

        c_seq = 1000
        s_seq = 2000
        client_src = (client["src_raw"], client["sport"])
        for ts_sec, ts_usec, _rank, _order, src_raw, dst_raw, sport, dport, flags, payload in sorted(events):
            is_client = (src_raw, sport) == client_src
            seq = c_seq if is_client else s_seq
            ack = 0 if flags == 0x02 else (s_seq if is_client else c_seq)
            if payload:
                data, seq = _emit_message(src_raw, dst_raw, sport, dport, seq, ack, payload)
            else:
                data = [_tcp_segment(src_raw, dst_raw, sport, dport, seq, ack, flags, b"")]
                if flags & 0x03:
                    seq = (seq + 1) & 0xFFFFFFFF
            if is_client:
                c_seq = seq
            else:
                s_seq = seq
            for piece in data:
                frames.append((ts_sec, ts_usec, piece))

    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113))
    for ts_sec, ts_usec, frame in frames:
        usec = ts_usec
        sec = ts_sec
        if usec >= 1000000:
            sec += usec // 1000000
            usec %= 1000000
        out += struct.pack("<IIII", sec & 0xFFFFFFFF, usec, len(frame), len(frame))
        out += frame
    Path(out_path).write_bytes(out)
    return out_path


def decrypted_pcap_path(pcap_path):
    path = Path(pcap_path)
    return path.with_name(path.stem + "_decrypted.pcap")


class App(tk.Tk):
    def __init__(self, pcap, keys):
        super().__init__()
        self.title("CarPlay 7000 解密")
        self.geometry("1100x760")
        self.pcap = tk.StringVar(value=str(pcap))
        self.keys = tk.StringVar(value=str(keys))
        self.status = tk.StringVar(value="选择 pcap 和密钥文件，然后点解密")

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="pcap").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.pcap).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="浏览", command=self._pick_pcap).grid(row=0, column=2)
        ttk.Label(top, text="密钥").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(top, textvariable=self.keys).grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="浏览", command=self._pick_keys).grid(row=1, column=2)
        top.columnconfigure(1, weight=1)

        bar = ttk.Frame(self, padding=(8, 0))
        bar.pack(fill="x")
        ttk.Button(bar, text="解密", command=self._decrypt).pack(side="left")
        ttk.Button(bar, text="保存明文", command=self._save).pack(side="left", padx=8)
        ttk.Label(bar, textvariable=self.status).pack(side="left", padx=8)

        self.text = scrolledtext.ScrolledText(self, wrap="none", font=("Consolas", 10))
        self.text.pack(fill="both", expand=True, padx=8, pady=8)
        self.result = ""

    def _pick_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("pcap", "*.pcap"), ("全部", "*.*")])
        if path:
            self.pcap.set(path)

    def _pick_keys(self):
        path = filedialog.askopenfilename(filetypes=[("txt", "*.txt"), ("全部", "*.*")])
        if path:
            self.keys.set(path)

    def _decrypt(self):
        try:
            reports = decrypt_pcap(self.pcap.get(), self.keys.get())
            self.result = format_report(reports)
        except Exception as exc:
            messagebox.showerror("解密失败", str(exc))
            self.status.set(f"失败: {exc}")
            return
        self.text.delete("1.0", "end")
        self.text.insert("1.0", self.result)
        frames = sum(side["frames"] for report in reports for side in report["sides"])
        out_pcap = decrypted_pcap_path(self.pcap.get())
        write_decrypted_pcap(reports, out_pcap)
        self.status.set(f"完成，解开 {frames} 帧，已写入 {out_pcap}")

    def _save(self):
        if not self.result:
            messagebox.showinfo("保存", "先解密")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="carplay_7000_plain.txt",
            filetypes=[("txt", "*.txt")],
        )
        if path:
            Path(path).write_text(self.result, encoding="utf-8")
            self.status.set(f"已保存 {path}")


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="解密 CarPlay TCP 7000 控制通道")
    parser.add_argument("--pcap", default=str(here / "carplay_7000.pcap"))
    parser.add_argument("--keys", default=str(here / "carplay_pair_verify_keys.txt"))
    parser.add_argument("--cli", action="store_true", help="打印到终端，不打开窗口")
    args = parser.parse_args()
    if args.cli:
        reports = decrypt_pcap(args.pcap, args.keys)
        out = format_report(reports)
        out_pcap = decrypted_pcap_path(args.pcap)
        write_decrypted_pcap(reports, out_pcap)
        sys.stdout.buffer.write(out.encode("utf-8", errors="replace"))
        sys.stderr.write(f"\n{out_pcap}\n")
        return
    App(args.pcap, args.keys).mainloop()


if __name__ == "__main__":
    main()
