btp_proto = Proto("btp", "Bitnomial Trading Protocol")

disconnect_reason_string = {
    [0x01] = "Sequence ID fault",
    [0x02] = "Heartbeat fault",
    [0x03] = "Failed to login within one (1) second",
    [0x04] = "Messaging rate exceeded",
    [0x05] = "Failed to parse message"
}

reject_reason_string = {
    [0x01] = "Not logged in",
    [0x02] = "Unauthorized",
    [0x03] = "Already logged in"
}

protocol_id = ProtoField.string("btp.protocol_id", "Protocol ID", base.ASCII)
version = ProtoField.uint16("btp.version", "Version", base.DEC)
sequence_id = ProtoField.uint32("btp.sequence_id", "Sequence ID", base.DEC)
body_encoding = ProtoField.string("btp.body_encoding", "Body Encoding",
                                  base.ASCII)
body_length = ProtoField.uint16("btp.body_length", "Body Length", base.DEC)
message_type = ProtoField.string("btp.message_type", "Message Type", base.ASCII)
product_id = ProtoField.uint64("btp.product_id", "Product ID", base.DEC)
disconnect_reason = ProtoField.uint8("btp.disconnect_reason",
                                     "Disconnect Reason", base.HEX,
                                     disconnect_reason_string)
expected_sequence_id = ProtoField.uint32("btp.expected_sequence_id",
                                         "Expected Sequence ID", base.DEC)
actual_sequence_id = ProtoField.uint32("btp.actual_sequence_id",
                                       "Actual Sequence ID", base.DEC)
connection_id =
    ProtoField.uint64("btp.connection_id", "Connection ID", base.DEC)
auth_token = ProtoField.bytes("btp.auth_token", "Auth Token")
heartbeat_interval = ProtoField.uint8("btp.heartbeat_interval",
                                      "Heartbeat Interval")
persist_orders = ProtoField.char("btp.persist_orders", "Persist Orders")
reject_reason = ProtoField.uint8("btp.reject_reason", "Reject Reason", base.HEX,
                                 reject_reason_string)
market_state = ProtoField.string("btp.market_state", "Market State", base.ASCII)
ack_id = ProtoField.uint64("btp.ack_id", "Ack ID", base.DEC)
side = ProtoField.string("btp.side", "Taker Side", base.ASCII)
price = ProtoField.int32("btp.price", "Price", base.DEC)
quantity = ProtoField.uint32("btp.quantity", "Quantity", base.DEC)
bids_length = ProtoField.uint64("btp.bids_length", "Bids Length")
bid_levels = ProtoField.bytes("btp.bid_levels", "Bid Levels")
asks_length = ProtoField.uint64("btp.asks_length", "Asks Length")
ask_levels = ProtoField.bytes("btp.ask_levels", "Ask Levels")
order_id = ProtoField.uint64("btp.order_id", "Order ID")
account_id_len = ProtoField.uint8("btp.account_id_len", "Account ID Length", base.DEC)
account_id = ProtoField.string("btp.account_id", "Account ID", base.ASCII)
cti_type = ProtoField.uint8("btp.cti_type", "CTI Type", base.DEC)
firm_name_len = ProtoField.uint8("btp.firm_name_len", "Firm Name Length", base.DEC)
firm_name = ProtoField.string("btp.firm_name", "Firm Name", base.ASCII)
firm_type = ProtoField.string("btp.firm_type", "Firm Type", base.ASCII)
user_memo_len = ProtoField.uint8("btp.user_memo_len", "User Memo Length", base.DEC)
user_memo = ProtoField.string("btp.user_memo", "User Memo", base.ASCII)
modify_id = ProtoField.uint64("btp.modify_id", "Modify ID", base.DEC)
old_price = ProtoField.int32("btp.old_price", "Old Price", base.DEC)
old_quantity = ProtoField.uint32("btp.old_quantity", "Old Quantity", base.DEC)
filled_quantity = ProtoField.uint32("btp.filled_quantity", "Filled Quantity", base.DEC)
liquidity = ProtoField.string("btp.liquidity", "Liquidity", base.ASCII)

function dissect_order_entry(buffer, pinfo, tree)
    -- TODO
end

function dissect_drop_copy(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    mt = buffer:range(0, 1):string()
    if mt == "O" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(connection_id, buffer:range(17, 8))
        tree:add_le(product_id, buffer:range(25, 8))
        tree:add_le(side, buffer:range(33, 1))
        tree:add_le(price, buffer:range(34, 4))
        tree:add_le(quantity, buffer:range(38, 4))
        tree:add_le(account_id_len, buffer:range(42, 1))
        tree:add_le(account_id, buffer:range(43, 10))
        tree:add_le(cti_type, buffer:range(53, 1))
        tree:add_le(firm_name_len, buffer:range(54, 1))
        tree:add_le(firm_name, buffer:range(55, 2))
        tree:add_le(firm_type, buffer:range(57, 1))
        tree:add_le(user_memo_len, buffer:range(58, 1))
        tree:add_le(user_memo, buffer:range(59, 20))
    elseif mt == "M" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(modify_id, buffer:range(17, 8))
        tree:add_le(connection_id, buffer:range(25, 8))
        tree:add_le(product_id, buffer:range(33, 8))
        tree:add_le(side, buffer:range(41, 1))
        tree:add_le(price, buffer:range(42, 4))
        tree:add_le(old_price, buffer:range(46, 4))
        tree:add_le(quantity, buffer:range(50, 4))
        tree:add_le(old_quantity, buffer:range(54, 4))
        tree:add_le(filled_quantity, buffer:range(58, 4))
        tree:add_le(account_id_len, buffer:range(62, 1))
        tree:add_le(account_id, buffer:range(63, 10))
        tree:add_le(cti_type, buffer:range(73, 1))
        tree:add_le(firm_name_len, buffer:range(74, 1))
        tree:add_le(firm_name, buffer:range(75, 2))
        tree:add_le(firm_type, buffer:range(77, 1))
        tree:add_le(user_memo_len, buffer:range(78, 1))
        tree:add_le(user_memo, buffer:range(79, 20))
    elseif mt == "F" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(price, buffer:range(17, 4))
        tree:add_le(quantity, buffer:range(21, 4))
        tree:add_le(filled_quantity, buffer:range(25, 4))
        tree:add_le(liquidity, buffer:range(29, 1))
        tree:add_le(connection_id, buffer:range(30, 8))
        tree:add_le(product_id, buffer:range(38, 8))
        tree:add_le(side, buffer:range(46, 1))
        tree:add_le(account_id_len, buffer:range(47, 1))
        tree:add_le(account_id, buffer:range(48, 10))
        tree:add_le(cti_type, buffer:range(58, 1))
        tree:add_le(firm_name_len, buffer:range(59, 1))
        tree:add_le(firm_name, buffer:range(60, 2))
        tree:add_le(firm_type, buffer:range(62, 1))
        tree:add_le(user_memo_len, buffer:range(63, 1))
        tree:add_le(user_memo, buffer:range(64, 20))
    elseif mt == "C" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(close_reason, buffer:range(17, 1))
        tree:add_le(connection_id, buffer:range(18, 8))
        tree:add_le(product_id, buffer:range(26, 8))
        tree:add_le(side, buffer:range(34, 1))
        tree:add_le(price, buffer:range(35, 4))
        tree:add_le(account_id_len, buffer:range(39, 1))
        tree:add_le(account_id, buffer:range(40, 10))
        tree:add_le(cti_type, buffer:range(50, 1))
        tree:add_le(firm_name_len, buffer:range(51, 1))
        tree:add_le(firm_name, buffer:range(52, 2))
        tree:add_le(firm_type, buffer:range(54, 1))
        tree:add_le(user_memo_len, buffer:range(55, 1))
        tree:add_le(user_memo, buffer:range(56, 20))
    end
end

function dissect_levels(length, buffer, pinfo, tree)
    for i = 0, length, 8 do
        tree:add_le(price, buffer:range(i, 4))
        tree:add_le(quantity, buffer:range(i + 4, 4))
    end
end

function dissect_pricefeed(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    mt = buffer:range(0, 1):string()
    if mt == "T" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(product_id, buffer:range(9, 8))
        tree:add_le(side, buffer:range(17, 1))
        tree:add_le(price, buffer:range(18, 4))
        tree:add_le(quantity, buffer:range(22, 4))
    elseif mt == "L" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(product_id, buffer:range(9, 8))
        tree:add_le(side, buffer:range(17, 1))
        tree:add_le(price, buffer:range(18, 4))
        tree:add_le(quantity, buffer:range(22, 4))
    elseif mt == "B" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(product_id, buffer:range(9, 8))

        tree:add_le(bids_length, buffer:range(17, 4))
        length = buffer:range(17, 4):uint()
        buf1 = buffer:range(21, length)
        subtree = tree:add_le(bid_levels, buf1)
        dissect_levels(length, buf2, pinfo, subtree)

        tree:add_le(asks_length, buffer:range(21 + length, 4))
        length2 = buffer:range(21 + length, 4):uint()
        buf2 = buffer:range(21 + length, length2)
        subtree = tree:add_le(ask_levels, buf2)
        dissect_levels(length2, buf2, pinfo, subtree)
    end
end

function dissect_login(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    mt = buffer:range(0, 1):string()
    if mt == "L" then
        tree:add_le(connection_id, buffer:range(1, 8))
        tree:add_le(auth_token, buffer:range(9, 32))
        tree:add_le(heartbeat_interval, buffer:range(41, 1))
    elseif mt == "K" then
        tree:add_le(persist_orders, buffer:range(1, 1))
    elseif mt == "A" then
        -- stub
    elseif mt == "R" then
        tree:add_le(reject_reason, buffer:range(1, 1))
    end
end

function dissect_market_state(buffer, pinfo, tree)
    tree:add_le(market_state, buffer:range(0, 1))
    tree:add_le(product_id, buffer:range(1, 8))
end

function dissect_heartbeat(buffer, pinfo, tree)
    -- this function intentionally left blank
end

function dissect_disconnect(buffer, pinfo, tree)
    tree:add_le(disconnect_reason, buffer:range(0, 1))
    tree:add_le(expected_sequence_id, buffer:range(1, 4))
    tree:add_le(actual_sequence_id, buffer:range(5, 4))
end

-- table of body encodings to body dissectors
body_dissectors = {
    ["OE"] = dissect_order_entry,
    ["DC"] = dissect_drop_copy,
    ["PF"] = dissect_pricefeed,
    ["LG"] = dissect_login,
    ["MS"] = dissect_market_state,
    ["HB"] = dissect_heartbeat,
    ["DN"] = dissect_disconnect
}

-- Invoke the body dissector for the given encoding type
function dissect_body(encoding, buffer, pinfo, tree)
    body_dissectors[encoding](buffer, pinfo, tree)
end

-- List of BTP fields
btp_proto.fields = {
    -- Header fields
    protocol_id, version, sequence_id, body_encoding, body_length,
    -- Disconnect fields
    disconnect_reason, expected_sequence_id, actual_sequence_id,
    -- Login fields
    message_type, connection_id, auth_token, heartbeat_interval, persist_orders,
    reject_reason
}

-- This function dissects BTP packets
function btp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 12 then -- ignore packets that are less than 12 bytes
        return
    end

    pinfo.cols.protocol = btp_proto.name

    -- dissect header
    subtree = tree:add(btp_proto, buffer:range(), "Bitnomial Trading Protocol")
    header = subtree:add_le(btp_proto, buffer:range(0, 12), "BTP Header")
    header:add_le(protocol_id, buffer:range(0, 2))
    header:add_le(version, buffer:range(2, 2))
    header:add_le(sequence_id, buffer:range(4, 4))
    header:add_le(body_encoding, buffer:range(8, 2))
    header:add_le(body_length, buffer:range(10, 2))

    -- dissect body based on the encoding
    body = subtree:add_le(btp_proto, buffer:range(12), "BTP Body")
    encoding = buffer:range(8, 2):string()
    dissect_body(encoding, buffer:range(12), pinfo, body)
end

-- This function matches packets against a series of tests to determine whether
-- or not the packet is a BTP packet
local function heuristic_checker(buffer, pinfo, tree)
    -- ensure that we have at least the minimum packet size
    length = buffer:len()
    if length < 12 then return false end

    -- ensure that the protocol ID matches
    protocol = buffer:range(0, 2):string()
    if protocol ~= "BT" then return false end

    -- ensure that the protocol version is version 2
    version = buffer:range(2, 2):uint16()
    if protocol ~= 2 then return false end

    -- ensure that the body encoding is valid
    encoding = buffer:range(8, 2):string()
    if body_dissectors[encoding] == nil then return false end

    -- invoke dissector
    btp_proto.dissector(buffer, pinfo, tree)
    return true
end

-- TODO heuristic_checker and btp_proto.dissector can be 
-- refactored to reduce duplicated behavior, for efficiency and
-- maintainability. In particular, a dissect header function
-- can be introduced that gets the relevant fields and populates
-- tree in one go

-- register our heuristic checker
btp_proto:register_heuristic("tcp", heuristic_checker)
