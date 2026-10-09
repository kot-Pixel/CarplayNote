-- AirPlay 屏幕流：128 字节帧头 + bodySize 载荷。
-- 用法：Wireshark 帮助 → 关于 → 文件夹 → Personal Lua Plugins，把本文件放进去后重启。
-- 一条流的第一段必须是 VideoConfig，且载荷里能看到 hvc1 或 avc1。
-- 包列表仍是每个 TCP 段一行；点开后协议树按帧切开。跨段的帧显示在收齐的那个包上。

local screen = Proto("airplayscreen", "AirPlay Screen")

local opcodes = {
    [0] = "VideoFrame",
    [1] = "VideoConfig",
    [2] = "KeepAlive",
    [3] = "ForceKeyFrame",
    [4] = "Ignore",
    [5] = "KeepAliveWithBody",
}

local FLAG_NAMES = {
    [0] = "ShowHUD",
    [1] = "RespectTimestamps",
    [2] = "Encrypted",
    [3] = "UseFormatDescription",
    [4] = "Unused4",
    [5] = "Suspended",
    [6] = "ClearScreen",
    [7] = "InterestingFrame",
}

local f_body = ProtoField.uint32("airplayscreen.body_size", "Body Size", base.DEC)
local f_opcode = ProtoField.uint8("airplayscreen.opcode", "Opcode", base.DEC, opcodes)
local f_flags = ProtoField.uint8("airplayscreen.flags", "Flags", base.HEX)
local f_pts = ProtoField.uint64("airplayscreen.pts", "PTS", base.DEC)
local f_pts_text = ProtoField.string("airplayscreen.pts_ntp", "PTS (NTP)")
local f_reencode = ProtoField.uint32("airplayscreen.reencode", "Reencode Count", base.DEC)
local f_width = ProtoField.float("airplayscreen.width", "Width")
local f_height = ProtoField.float("airplayscreen.height", "Height")
local f_origin_x = ProtoField.float("airplayscreen.origin_x", "View Origin X")
local f_origin_y = ProtoField.float("airplayscreen.origin_y", "View Origin Y")
local f_view_w = ProtoField.float("airplayscreen.view_w", "View Width")
local f_view_h = ProtoField.float("airplayscreen.view_h", "View Height")
local f_codec = ProtoField.string("airplayscreen.codec", "Codec")
local f_payload = ProtoField.bytes("airplayscreen.payload", "Payload")

screen.fields = {
    f_body, f_opcode, f_flags, f_pts, f_pts_text, f_reencode,
    f_width, f_height, f_origin_x, f_origin_y, f_view_w, f_view_h,
    f_codec, f_payload,
}

local function flag_text(flags)
    local names = {}
    for bitn = 0, 7 do
        if math.floor(flags / (2 ^ bitn)) % 2 == 1 then
            names[#names + 1] = FLAG_NAMES[bitn]
        end
    end
    if #names == 0 then
        return "0"
    end
    return table.concat(names, ",")
end

local function pdu_len(tvb, pinfo, offset)
    return 128 + tvb(offset, 4):le_uint()
end

local function fmt_float(value)
    return string.format("%.0f", value)
end

local function dissect_one(tvb, pinfo, tree)
    local body = tvb(0, 4):le_uint()
    local opcode = tvb(4, 1):uint()
    local name = opcodes[opcode] or string.format("Unknown(%d)", opcode)
    local subtree = tree:add(screen, tvb(), name)
    subtree:add_le(f_body, tvb(0, 4))
    subtree:add(f_opcode, tvb(4, 1))

    local info = name
    if opcode == 0 then
        local frac = tvb(8, 4):le_uint()
        local secs = tvb(12, 4):le_uint()
        subtree:add_le(f_pts, tvb(8, 8))
        subtree:add(f_pts_text, string.format("%u + %u/2^32", secs, frac))
        subtree:add_le(f_reencode, tvb(24, 4))
        info = string.format("VideoFrame body=%u pts=%u", body, secs)
    elseif opcode == 1 then
        local flags = tvb(6, 1):uint()
        local width = tvb(16, 4):le_float()
        local height = tvb(20, 4):le_float()
        subtree:add(f_flags, tvb(6, 1)):append_text(" (" .. flag_text(flags) .. ")")
        subtree:add_le(f_width, tvb(16, 4))
        subtree:add_le(f_height, tvb(20, 4))
        subtree:add_le(f_origin_x, tvb(32, 4))
        subtree:add_le(f_origin_y, tvb(36, 4))
        subtree:add_le(f_view_w, tvb(40, 4))
        subtree:add_le(f_view_h, tvb(44, 4))
        if body >= 8 and tvb:len() >= 136 then
            local fourcc = tvb(132, 4):string()
            if fourcc == "hvc1" or fourcc == "avc1" then
                subtree:add(f_codec, fourcc)
                info = string.format("VideoConfig %s %.0fx%.0f %s", fourcc, width, height, flag_text(flags))
            else
                info = string.format("VideoConfig %.0fx%.0f %s", width, height, flag_text(flags))
            end
        else
            info = string.format("VideoConfig %.0fx%.0f %s", width, height, flag_text(flags))
        end
    else
        info = string.format("%s body=%u", name, body)
    end

    if body > 0 and tvb:len() >= 128 + body then
        subtree:add(f_payload, tvb(128, body))
    end

    pinfo.cols.protocol = "AirPlay Screen"
    if tostring(pinfo.cols.info) == "" or not tostring(pinfo.cols.info):find("AirPlay", 1, true) then
        pinfo.cols.info = info
    else
        pinfo.cols.info:append(" | " .. info)
    end
end

function screen.dissector(tvb, pinfo, tree)
    dissect_tcp_pdus(tvb, tree, 128, pdu_len, dissect_one)
end

local function looks_like_config(tvb)
    if tvb:len() < 136 then
        return false
    end
    local body = tvb(0, 4):le_uint()
    local opcode = tvb(4, 1):uint()
    if opcode ~= 1 or body < 8 or body > 4096 then
        return false
    end
    local fourcc = tvb(132, 4):string()
    return fourcc == "hvc1" or fourcc == "avc1"
end

screen:register_heuristic("tcp", function(tvb, pinfo, tree)
    if not looks_like_config(tvb) then
        return false
    end
    screen.dissector(tvb, pinfo, tree)
    return true
end)
