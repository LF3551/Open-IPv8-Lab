-- IPv8 Lab Wireshark dissector
-- Place in ~/.local/lib/wireshark/plugins/ (Linux)
-- or ~/Library/Application Support/Wireshark/plugins/ (macOS)
-- or %APPDATA%\Wireshark\plugins\ (Windows)

local ipv8 = Proto("ipv8", "IPv8 Protocol (draft-thain-ipv8-00)")

-- Header fields
local f_version   = ProtoField.uint8("ipv8.version", "Version", base.DEC, nil, 0xF0)
local f_ihl       = ProtoField.uint8("ipv8.ihl", "IHL (32-bit words)", base.DEC, nil, 0x0F)
local f_tos       = ProtoField.uint8("ipv8.tos", "Type of Service", base.HEX)
local f_total_len = ProtoField.uint16("ipv8.total_length", "Total Length", base.DEC)
local f_ident     = ProtoField.uint16("ipv8.identification", "Identification", base.HEX)
local f_flags     = ProtoField.uint16("ipv8.flags", "Flags", base.HEX, nil, 0xE000)
local f_frag      = ProtoField.uint16("ipv8.frag_offset", "Fragment Offset", base.DEC, nil, 0x1FFF)
local f_ttl       = ProtoField.uint8("ipv8.ttl", "Time to Live", base.DEC)
local f_proto     = ProtoField.uint8("ipv8.protocol", "Protocol", base.DEC)
local f_checksum  = ProtoField.uint16("ipv8.checksum", "Header Checksum", base.HEX)
local f_src_asn   = ProtoField.uint32("ipv8.src_asn", "Source ASN Prefix", base.DEC)
local f_src_host  = ProtoField.ipv4("ipv8.src_host", "Source Host")
local f_dst_asn   = ProtoField.uint32("ipv8.dst_asn", "Destination ASN Prefix", base.DEC)
local f_dst_host  = ProtoField.ipv4("ipv8.dst_host", "Destination Host")
local f_payload   = ProtoField.bytes("ipv8.payload", "Payload")

ipv8.fields = {
    f_version, f_ihl, f_tos, f_total_len, f_ident,
    f_flags, f_frag, f_ttl, f_proto, f_checksum,
    f_src_asn, f_src_host, f_dst_asn, f_dst_host, f_payload
}

function ipv8.dissector(buffer, pinfo, tree)
    if buffer:len() < 28 then return end

    pinfo.cols.protocol = "IPv8"

    local subtree = tree:add(ipv8, buffer(), "IPv8 Protocol")

    local ver_ihl = buffer(0, 1):uint()
    local version = bit.rshift(ver_ihl, 4)
    local ihl = bit.band(ver_ihl, 0x0F)

    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_ihl, buffer(0, 1))
    subtree:add(f_tos, buffer(1, 1))
    subtree:add(f_total_len, buffer(2, 2))
    subtree:add(f_ident, buffer(4, 2))
    subtree:add(f_flags, buffer(6, 2))
    subtree:add(f_frag, buffer(6, 2))
    subtree:add(f_ttl, buffer(8, 1))
    subtree:add(f_proto, buffer(9, 1))
    subtree:add(f_checksum, buffer(10, 2))

    local src_asn = buffer(12, 4):uint()
    local dst_asn = buffer(20, 4):uint()
    subtree:add(f_src_asn, buffer(12, 4))
    subtree:add(f_src_host, buffer(16, 4))
    subtree:add(f_dst_asn, buffer(20, 4))
    subtree:add(f_dst_host, buffer(24, 4))

    local total_len = buffer(2, 2):uint()
    local hdr_len = ihl * 4
    if total_len > hdr_len and buffer:len() > hdr_len then
        local payload_len = math.min(total_len - hdr_len, buffer:len() - hdr_len)
        subtree:add(f_payload, buffer(hdr_len, payload_len))
    end

    -- Info column
    pinfo.cols.info = string.format(
        "AS%d.%s → AS%d.%s",
        src_asn, tostring(buffer(16, 4):ipv4()),
        dst_asn, tostring(buffer(24, 4):ipv4())
    )
end

-- Register for DLT_USER0 (147)
local wtap = DissectorTable.get("wtap_encap")
wtap:add(147, ipv8)
