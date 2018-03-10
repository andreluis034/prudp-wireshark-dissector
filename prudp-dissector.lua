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

local possible_starts = {
    { 
        pattern = {0xAF, 0xA1},-- Client to Server V0
        version = 0
    }, 
    { 
        pattern = {0xA1, 0xAF},-- Server to Client V0
        version = 0
    }, 
    { 
        pattern = {0xEA, 0xD0, 0x01},-- Client to Server V0
        version = 1
    }
}
local startv0_1 = {}

local prudp = Proto("prudp","Nintendo prudp protocol")

local unknown8 = ProtoField.new("UNKNOWN", "prudp.unknown8", ftypes.UINT8, nil, base.HEX)


local prudp_v0_source      = ProtoField.new("Source", "prudp.v0.source", ftypes.UINT8, identities, base.HEX)
local prudp_v0_destination = ProtoField.new("Destination", "prudp.v0.destination", ftypes.UINT8, identities, base.HEX)
local prudp_v0_flags       = ProtoField.new("Flags", "prudp.v0.flags", ftypes.UINT16, nil, base.HEX)

local prudp_v0_type = ProtoField.new("Packet Type", "prudp.v0.type", ftypes.UINT16, types_inverse, base.DEC, 0x0F00)

local prudp_v0_flags_ack       = ProtoField.new("Acknowledge", "prudp.v0.flags.acknowledge", ftypes.BOOLEAN, {"yes","no"}, 16, 0x1000)
local prudp_v0_flags_reliable  = ProtoField.new("Reliable", "prudp.v0.flags.reliable", ftypes.BOOLEAN, {"yes","no"}, 16, 0x2000)
local prudp_v0_flags_need_ack  = ProtoField.new("Need acknowledge", "prudp.v0.flags.need_ack", ftypes.BOOLEAN, {"yes","no"}, 16, 0x4000)
local prudp_v0_flags_has_size  = ProtoField.new("Has size", "prudp.v0.flags.has_size", ftypes.BOOLEAN, {"yes","no"}, 16, 0x8000)
local prudp_v0_flags_multi_ack = ProtoField.new("Multi ack", "prudp.v0.flags.multi_ack", ftypes.BOOLEAN, {"yes","no"}, 16, 0x0020) --No idea how to parse this

local prudp_v0_sessionid = ProtoField.new("Session ID", "prudp.v0.sessionid", ftypes.UINT8, nil, base.HEX)
local prudp_v0_packet_signature = ProtoField.new("Packet Signature", "prudp.v0.packet_signature", ftypes.UINT32, nil, base.HEX)
local prudp_v0_sequenceid = ProtoField.new("Sequence ID", "prudp.v0.sequenceid", ftypes.UINT16, nil, base.HEX)

local prudp_v0_payload = ProtoField.new("Payload", "prudp.v0.payload", ftypes.BYTES, nil, base.NONE)
local prudp_v0_checksum = ProtoField.new("Checksum", "prudp.v0.checksum", ftypes.UINT8, nil, base.HEX)

local prudp_v0_connection_signature = ProtoField.new("Connection Signature", "prudp.v0.connection_signature", ftypes.UINT32, nil, base.HEX)
local prudp_v0_fragmentid = ProtoField.new("Fragment ID", "prudp.v0.fragmentid", ftypes.UINT8, nil, base.HEX)
local prudp_v0_payloadsize = ProtoField.new("Payload size", "prudp.v0.payloadsize", ftypes.UINT16, nil, base.HEX)

local prudp_v1_header = ProtoField.new("Header", "prudp.v1.header", ftypes.BYTES, nil, base.NONE)
local prudp_v1_header_version = ProtoField.new("Version", "prudp.v1.header.version", ftypes.UINT8, nil, base.DEC)
local prudp_v1_header_extradatasize = ProtoField.new("Extra packet size", "prudp.v1.header.extradatasize", ftypes.UINT8, nil, base.HEX)
local prudp_v1_header_payloadsize = ProtoField.new("Payload size", "prudp.v1.header.payloadsize", ftypes.UINT16, nil, base.HEX)
local prudp_v1_header_source = ProtoField.new("Source", "prudp.v1.header.source", ftypes.UINT8, identities, base.HEX)
local prudp_v1_header_destination = ProtoField.new("Destination", "prudp.v1.header.destination", ftypes.UINT8, identities, base.HEX)
local prudp_v1_header_sessionid = ProtoField.new("Session ID", "prudp.v1.header.sessionid", ftypes.UINT8, nil, base.HEX)
local prudp_v1_header_sequenceid = ProtoField.new("Sequence ID", "prudp.v1.header.sequenceid", ftypes.UINT16, nil, base.HEX)

local prudp_v1_hash = ProtoField.new("Hash", "prudp.v1.hash", ftypes.BYTES, nil, base.NONE)

prudp.fields = {
    unknown8,
    prudp_v0_source,
    prudp_v0_destination,
    prudp_v0_type,
    prudp_v0_flags,
    prudp_v0_flags_ack,
    prudp_v0_flags_reliable,
    prudp_v0_flags_need_ack,
    prudp_v0_flags_has_size,
    prudp_v0_flags_multi_ack,
    prudp_v0_sessionid,
    prudp_v0_packet_signature,
    prudp_v0_sequenceid,
    prudp_v0_connection_signature,
    prudp_v0_payload,
    prudp_v0_checksum,
    prudp_v0_fragmentid,
    prudp_v0_payloadsize,
    prudp_v1_header,
    prudp_v1_header_version,
    prudp_v1_header_extradatasize,
    prudp_v1_header_payloadsize,
    prudp_v1_header_source,
    prudp_v1_header_destination,
    prudp_v1_header_sessionid,
    prudp_v1_header_sequenceid,
    prudp_v1_hash
}

local fields = {
    flags = {
        acknowledge = Field.new("prudp.v0.flags.acknowledge"),
        reliable    = Field.new("prudp.v0.flags.reliable"),
        need_ack    = Field.new("prudp.v0.flags.need_ack"),
        has_size    = Field.new("prudp.v0.flags.has_size"),
    },
    type = Field.new("prudp.v0.type"),
    payloadsize = Field.new("prudp.v0.payloadsize"),
    source = Field.new("prudp.v0.source"),
    destination = Field.new("prudp.v0.destination"),
    v1 = {
        extradatasize = Field.new("prudp.v1.extradatasize")
    }
}

function dissectv0(tvbuf, pktinfo, root)
    local currentPosition = 0
    local remaining = 0
    pktinfo.cols.protocol:set("PRUDP - V0")
    local pktlen = tvbuf:reported_length_remaining()

    local tree = root:add(prudp, tvbuf:range(0,pktlen))

    tree:add(prudp_v0_source, tvbuf:range(0,1))
    tree:add(prudp_v0_destination, tvbuf:range(1,1))
    local flagrange = tvbuf:range(2,2)
    tree:add(prudp_v0_type, flagrange)
    
    local flag_tree = tree:add(prudp_v0_flags, flagrange)
    flag_tree:add(prudp_v0_flags_ack, flagrange)
    flag_tree:add(prudp_v0_flags_reliable, flagrange)
    flag_tree:add(prudp_v0_flags_need_ack, flagrange)
    flag_tree:add(prudp_v0_flags_has_size, flagrange)
    flag_tree:add(prudp_v0_flags_multi_ack, flagrange)


    tree:add_le(prudp_v0_sessionid, tvbuf:range(0x4, 1))
    tree:add_le(prudp_v0_packet_signature, tvbuf:range(0x5, 4))
    tree:add_le(prudp_v0_sequenceid, tvbuf:range(0x9, 2))

    currentPosition = 0xB;
    if fields.type()() == types.CONNECT then
        pktinfo.cols.info:set("CONNECT "..identities[fields.source()()].." -> "..identities[fields.destination()()])
        tree:add_le(prudp_v0_connection_signature, tvbuf:range(currentPosition, 4))
        currentPosition = currentPosition + 4
    elseif fields.type()() == types.DATA then
        tree:add_le(prudp_v0_fragmentid, tvbuf:range(currentPosition, 1))
        currentPosition = currentPosition + 1
    end
    if fields.flags.has_size()() then
        tree:add_le(prudp_v0_payloadsize, tvbuf:range(currentPosition, 2))
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
        tree:add(prudp_v0_payload, tvbuf:range(currentPosition, remaining - 1))
        currentPosition = remaining - 1 + currentPosition
    end        

    tree:add(prudp_v0_checksum, tvbuf:range(pktlen - 1, 1))

    return pktlen
end
function dissectv1(tvbuf, pktinfo, root)
    local currentPosition = 0
    local remaining = 0
    local pktlen = tvbuf:reported_length_remaining()
    local tree = root:add(prudp, tvbuf:range(0,pktlen))
    local headertree = tree:add(prudp_v1_header, tvbuf:range(2,0xC))
    pktinfo.cols.protocol:set("PRUDP - V1")
    

    headertree:add(prudp_v1_header_version, tvbuf:range(2,1))
    headertree:add(prudp_v1_header_extradatasize, tvbuf:range(3,1))
    headertree:add_le(prudp_v1_header_payloadsize, tvbuf:range(4,2))
    headertree:add(prudp_v1_header_destination, tvbuf:range(6,1))
    headertree:add(prudp_v1_header_source, tvbuf:range(7,1))

    local flagrange = tvbuf:range(8,2)
    headertree:add(prudp_v0_type, flagrange)
    
    local flag_tree = headertree:add(prudp_v0_flags, flagrange)
    flag_tree:add(prudp_v0_flags_ack, flagrange)
    flag_tree:add(prudp_v0_flags_reliable, flagrange)
    flag_tree:add(prudp_v0_flags_need_ack, flagrange)
    flag_tree:add(prudp_v0_flags_has_size, flagrange)
    flag_tree:add(prudp_v0_flags_multi_ack, flagrange)


    headertree:add(prudp_v1_header_sessionid, tvbuf:range(10,1))
    headertree:add(unknown8, tvbuf:range(11,1))
    headertree:add_le(prudp_v1_header_sequenceid, tvbuf:range(12,2))
    
    tree:add(prudp_v1_hash, tvbuf(14,16))



    return pktlen
end

function prudp.dissector(tvbuf, pktinfo, root)
    for i = 1, #possible_starts do
        local result = startsWith(tvbuf, possible_starts[i])
        if result ~= -1 then
            return dissectors[result](tvbuf,pktinfo,root)
        end
    end
    return 0
end

local dissectors = {
    [0] = dissectv0,
    [1] = dissectv1
}

function startsWith(tvbuf, packet_header)
    local bytes = tvbuf:range(0, #packet_header.pattern):bytes()
    for i = 1, #packet_header.pattern do
        if (packet_header.pattern[i] ~= bytes:get_index(i-1)) then
            return -1
        end
    end
    return packet_header.version
end

function heuristic_prudp(tvbuf,pktinfo,root)
    for i = 1, #possible_starts do
        local result = startsWith(tvbuf, possible_starts[i])
        if result ~= -1 then
            dissectors[result](tvbuf,pktinfo,root)
            return true
        end
    end
    return false
end

prudp:register_heuristic("udp",heuristic_prudp)


