local identities = {
    [0xaf] = "Client",
    [0xa1] = "Server"
}

local types = {
    SYN = 0,
    CONNECT = 1,
    DATA = 2,
    DISCONNECT = 3,
    PING = 4,
}

local types_inverse = {
    [0] = "SYN",
    [1] = "CONNECT",
    [2] = "DATA",
    [3] = "DISCONNECT",
    [4] = "PING",
}

local prudp = Proto("prudp","Nintendo PRDUP protocol")
local prudp_source      = ProtoField.new("Source", "prudp.source", ftypes.UINT8, identities, base.HEX)
local prudp_destination = ProtoField.new("Destination", "prudp.destination", ftypes.UINT8, identities, base.HEX)
local prudp_flags       = ProtoField.new("Flags", "prudp.flags", ftypes.UINT16, nil, base.HEX)

local prudp_type = ProtoField.new("Packet Type", "prudp.type", ftypes.UINT16, types_inverse, base.DEC, 0x0F00)

local prudp_flags_ack       = ProtoField.new("Acknowledge", "prudp.flags.acknowledge", ftypes.BOOLEAN, {"yes","no"}, 16, 0x1000)
local prudp_flags_reliable  = ProtoField.new("Reliable", "prudp.flags.reliable", ftypes.BOOLEAN, {"yes","no"}, 16, 0x2000)
local prudp_flags_need_ack  = ProtoField.new("Need acknowledge", "prudp.flags.need_ack", ftypes.BOOLEAN, {"yes","no"}, 16, 0x4000)
local prudp_flags_has_size  = ProtoField.new("Has size", "prudp.flags.has_size", ftypes.BOOLEAN, {"yes","no"}, 16, 0x8000)
local prudp_flags_multi_ack = ProtoField.new("Multi ack", "prudp.flags.multi_ack", ftypes.BOOLEAN, {"yes","no"}, 16, 0x0020) --No idea how to parse this

local prdup_sessionid = ProtoField.new("Session ID", "prudp.sessionid", ftypes.UINT8, nil, base.HEX)
local prdup_packet_signature = ProtoField.new("Packet Signature", "prudp.packet_signature", ftypes.UINT32, nil, base.HEX)
local prdup_sequenceid = ProtoField.new("Sequence ID", "prudp.sequenceid", ftypes.UINT16, nil, base.HEX)

local prdup_payload = ProtoField.new("Payload", "prudp.payload", ftypes.BYTES, nil, base.NONE)
local prdup_checksum = ProtoField.new("Checksum", "prudp.checksum", ftypes.UINT8, nil, base.HEX)

local prdup_connection_signature = ProtoField.new("Connection Signature", "prudp.connection_signature", ftypes.UINT32, nil, base.HEX)
local prdup_fragmentid = ProtoField.new("Fragment ID", "prudp.fragmentid", ftypes.UINT8, nil, base.HEX)
local prdup_payloadsize = ProtoField.new("Payload size", "prudp.payloadsize", ftypes.UINT16, nil, base.HEX)
prudp.fields = {
    prudp_source,
    prudp_destination,
    prudp_type,
    prudp_flags,
    prudp_flags_ack,
    prudp_flags_reliable,
    prudp_flags_need_ack,
    prudp_flags_has_size,
    prudp_flags_multi_ack,
    prdup_sessionid,
    prdup_packet_signature,
    prdup_sequenceid,
    prdup_connection_signature,
    prdup_payload,
    prdup_checksum,
    prdup_fragmentid,
    prdup_payloadsize
}

local fields = {
    flags = {
        acknowledge = Field.new("prudp.flags.acknowledge"),
        reliable    = Field.new("prudp.flags.reliable"),
        need_ack    = Field.new("prudp.flags.need_ack"),
        has_size    = Field.new("prudp.flags.has_size"),
    },
    type = Field.new("prudp.type"),
    payloadsize = Field.new("prudp.payloadsize")
}
function prudp.dissector(tvbuf, pktinfo, root)
    local currentPosition = 0
    local remaining = 0
    pktinfo.cols.protocol:set("PRUDP")
    local pktlen = tvbuf:reported_length_remaining()

    local tree = root:add(prudp, tvbuf:range(0,pktlen))

    tree:add(prudp_source, tvbuf:range(0,1))
    tree:add(prudp_destination, tvbuf:range(1,1))
    local flagrange = tvbuf:range(2,2)
    tree:add(prudp_type, flagrange)
    
    local flag_tree = tree:add(prudp_flags, flagrange)
    flag_tree:add(prudp_flags_ack, flagrange)
    flag_tree:add(prudp_flags_reliable, flagrange)
    flag_tree:add(prudp_flags_need_ack, flagrange)
    flag_tree:add(prudp_flags_has_size, flagrange)
    flag_tree:add(prudp_flags_multi_ack, flagrange)


    tree:add_le(prdup_sessionid, tvbuf:range(0x4, 1))
    tree:add_le(prdup_packet_signature, tvbuf:range(0x5, 4))
    tree:add_le(prdup_sequenceid, tvbuf:range(0x9, 2))

    currentPosition = 0xB;
    if fields.type()() == types.CONNECT then
        tree:add_le(prdup_connection_signature, tvbuf:range(currentPosition, 4))
        currentPosition = currentPosition + 4
    elseif fields.type()() == types.DATA then
        tree:add_le(prdup_fragmentid, tvbuf:range(currentPosition, 1))
        currentPosition = currentPosition + 1
    end
    if fields.flags.has_size()() then
        tree:add_le(prdup_payloadsize, tvbuf:range(currentPosition, 2))
        currentPosition = currentPosition + 2
        remaining = pktlen - currentPosition
        
        if remaining - 1 < fields.payloadsize()() then
            critical("Remaining packet length different from payload size");
            critical("remaining " .. remaining);
            critical("payload size " .. fields.payloadsize()());
        else
            remaining = fields.payloadsize()() + 1
        end
    else
        remaining = pktlen - currentPosition
    end

    if remaining > 1 then
        message(remaining)
        tree:add(prdup_payload, tvbuf:range(currentPosition, remaining - 1))
        currentPosition = remaining - 1 + currentPosition
    end        

    tree:add(prdup_checksum, tvbuf:range(pktlen - 1, 1))

    return pktlen
end

DissectorTable.get("udp.port"):add(60000, prudp)
