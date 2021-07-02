local btp_proto = Proto("btp", "Bitnomial Trading Protocol")

local disconnect_reason_string = {
    [0x01] = "Sequence ID fault",
    [0x02] = "Heartbeat fault",
    [0x03] = "Failed to login within one (1) second",
    [0x04] = "Messaging rate exceeded",
    [0x05] = "Failed to parse message"
}

local login_reject_reason_string = {
    [0x01] = "Not logged in",
    [0x02] = "Unauthorized",
    [0x03] = "Already logged in"
}

local order_entry_reject_reason_string = {
    [0x01] = "Account not found",
    [0x02] = "Product not found",
    [0x03] = "Order not found",
    [0x04] = "Order already exists",
    [0x05] = "Order already closed",
    [0x06] = "Order not changed by modify",
    [0x07] = "Quantity greater than max order size",
    [0x08] = "Quantity less than min order size",
    [0x09] = "Price outside price bands",
    [0x0A] = "Price outside price limits",
    [0x0B] = "Price not tick aligned (reserved)",
    [0x0C] = "Market halted. Only close requests accepted",
    [0x0D] = "Market closed. No requests accepted",
    [0x0E] = "Give-up account not found",
    [0x0F] = "Give-up unauthorized",
    [0x10] = "Messaging rate exceeded",
    [0x11] = "Position limit exceeded",
    [0x12] = "Connection disabled"
}

local function be2int(be)
    if string.len(be) == 2 then
        local a = string.byte(be, 1)
        local b = string.byte(be, 2)
        return bit32.bor(bit32.lshift(b, 8), a)
    else
        error("btp.lua:be2int expected a string of exactly 2 characters")
    end
end

local body_encoding_string = {
    [be2int("OE")] = "Order Entry",
    [be2int("DC")] = "Drop Copy",
    [be2int("PF")] = "Price Feed",
    [be2int("LG")] = "Login",
    [be2int("MS")] = "Market State",
    [be2int("HB")] = "Heartbeat",
    [be2int("DN")] = "Disconnect"
}

local protocol_id = ProtoField.string("btp.protocol_id", "Protocol ID",
                                      base.ASCII, nil)
local version = ProtoField.uint16("btp.version", "Version", base.DEC, nil, nil,
                                  nil)
local sequence_id = ProtoField.uint32("btp.sequence_id", "Sequence ID",
                                      base.DEC, nil, nil, nil)
local body_encoding = ProtoField.uint16("btp.body_encoding", "Body Encoding",
                                        base.HEX, body_encoding_string, nil, nil)
local body_length =
    ProtoField.uint16("btp.body_length", "Body Length", base.DEC)
local message_type = ProtoField.string("btp.message_type", "Message Type",
                                       base.ASCII)
local product_id = ProtoField.uint64("btp.product_id", "Product ID", base.DEC)
local disconnect_reason = ProtoField.uint8("btp.disconnect_reason",
                                           "Disconnect Reason", base.HEX,
                                           disconnect_reason_string)
local expected_sequence_id = ProtoField.uint32("btp.expected_sequence_id",
                                               "Expected Sequence ID", base.DEC)
local actual_sequence_id = ProtoField.uint32("btp.actual_sequence_id",
                                             "Actual Sequence ID", base.DEC)
local connection_id = ProtoField.uint64("btp.connection_id", "Connection ID",
                                        base.DEC)
local auth_token = ProtoField.bytes("btp.auth_token", "Auth Token")
local heartbeat_interval = ProtoField.uint8("btp.heartbeat_interval",
                                            "Heartbeat Interval")
local persist_orders = ProtoField.char("btp.persist_orders", "Persist Orders")
local login_reject_reason = ProtoField.uint8("btp.login.reject_reason",
                                             "Reject Reason", base.HEX,
                                             login_reject_reason_string)
local market_state = ProtoField.string("btp.market_state", "Market State",
                                       base.ASCII)
local ack_id = ProtoField.uint64("btp.ack_id", "Ack ID", base.DEC)
local side = ProtoField.string("btp.side", "Taker Side", base.ASCII)
local price = ProtoField.int32("btp.price", "Price", base.DEC)
local quantity = ProtoField.uint32("btp.quantity", "Quantity", base.DEC)
local bids_length = ProtoField.uint64("btp.bids_length", "Bids Length")
local bid_levels = ProtoField.bytes("btp.bid_levels", "Bid Levels")
local asks_length = ProtoField.uint64("btp.asks_length", "Asks Length")
local ask_levels = ProtoField.bytes("btp.ask_levels", "Ask Levels")
local order_id = ProtoField.uint64("btp.order_id", "Order ID")
local account_id_len = ProtoField.uint8("btp.account_id_len",
                                        "Account ID Length", base.DEC)
local account_id = ProtoField.string("btp.account_id", "Account ID", base.ASCII)
local cti_type = ProtoField.uint8("btp.cti_type", "CTI Type", base.DEC)
local firm_name_len = ProtoField.uint8("btp.firm_name_len", "Firm Name Length",
                                       base.DEC)
local firm_name = ProtoField.string("btp.firm_name", "Firm Name", base.ASCII)
local firm_type = ProtoField.string("btp.firm_type", "Firm Type", base.ASCII)
local user_memo_len = ProtoField.uint8("btp.user_memo_len", "User Memo Length",
                                       base.DEC)
local user_memo = ProtoField.string("btp.user_memo", "User Memo", base.ASCII)
local modify_id = ProtoField.uint64("btp.modify_id", "Modify ID", base.DEC)
local old_price = ProtoField.int32("btp.old_price", "Old Price", base.DEC)
local old_quantity = ProtoField.uint32("btp.old_quantity", "Old Quantity",
                                       base.DEC)
local filled_quantity = ProtoField.uint32("btp.filled_quantity",
                                          "Filled Quantity", base.DEC)
local liquidity = ProtoField.string("btp.liquidity", "Liquidity", base.ASCII)
local close_reason = ProtoField.string("btp.close_reason", "Close Reason",
                                       base.ASCII)
local order_entry_reject_reason = ProtoField.uint8(
                                      "btp.order_entry.reject_reason",
                                      "Reject Reason", base.HEX,
                                      order_entry_reject_reason_string)
local time_in_force = ProtoField.string("btp.time_in_force", "Time in Force",
                                        base.ASCII)

local function dissect_order_entry(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    local mt = buffer:range(0, 1):string()
    if mt == "O" then
        tree:add_le(order_id, buffer:range(1, 8))
        tree:add_le(product_id, buffer:range(9, 8))
        tree:add_le(side, buffer:range(17, 1))
        tree:add_le(price, buffer:range(18, 4))
        tree:add_le(quantity, buffer:range(22, 4))
        tree:add_le(time_in_force, buffer:range(26, 1))
    elseif mt == "M" then
        tree:add_le(order_id, buffer:range(1, 8))
        tree:add_le(modify_id, buffer:range(9, 8))
        tree:add_le(price, buffer:range(17, 4))
        tree:add_le(quantity, buffer:range(21, 4))
    elseif mt == "A" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(modify_id, buffer:range(17, 8))
    elseif mt == "R" then
        tree:add_le(order_id, buffer:range(1, 8))
        tree:add_le(modify_id, buffer:range(9, 8))
        tree:add_le(order_entry_reject_reason, buffer:range(17, 1))
    elseif mt == "C" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(close_reason, buffer:range(17, 1))
    elseif mt == "F" then
        tree:add_le(ack_id, buffer:range(1, 8))
        tree:add_le(order_id, buffer:range(9, 8))
        tree:add_le(price, buffer:range(17, 4))
        tree:add_le(quantity, buffer:range(21, 4))
        tree:add_le(liquidity, buffer:range(25, 1))
    end
end

local function dissect_drop_copy(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    local mt = buffer:range(0, 1):string()
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

local function dissect_levels(length, buffer, pinfo, tree)
    for i = 0, length, 8 do
        tree:add_le(price, buffer:range(i, 4))
        tree:add_le(quantity, buffer:range(i + 4, 4))
    end
end

local function dissect_pricefeed(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    local mt = buffer:range(0, 1):string()
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

local function dissect_login(buffer, pinfo, tree)
    tree:add_le(message_type, buffer:range(0, 1))
    local mt = buffer:range(0, 1):string()
    if mt == "L" then
        tree:add_le(connection_id, buffer:range(1, 8))
        tree:add_le(auth_token, buffer:range(9, 32))
        tree:add_le(heartbeat_interval, buffer:range(41, 1))
    elseif mt == "K" then
        tree:add_le(persist_orders, buffer:range(1, 1))
    elseif mt == "A" then
        -- stub
    elseif mt == "R" then
        tree:add_le(login_reject_reason, buffer:range(1, 1))
    end
end

local function dissect_market_state(buffer, pinfo, tree)
    tree:add_le(market_state, buffer:range(0, 1))
    tree:add_le(product_id, buffer:range(1, 8))
end

local function dissect_heartbeat(buffer, pinfo, tree)
    -- this function intentionally left blank
end

local function dissect_disconnect(buffer, pinfo, tree)
    tree:add_le(disconnect_reason, buffer:range(0, 1))
    tree:add_le(expected_sequence_id, buffer:range(1, 4))
    tree:add_le(actual_sequence_id, buffer:range(5, 4))
end

-- table of body encodings to body dissectors
local body_dissectors = {
    ["OE"] = dissect_order_entry,
    ["DC"] = dissect_drop_copy,
    ["PF"] = dissect_pricefeed,
    ["LG"] = dissect_login,
    ["MS"] = dissect_market_state,
    ["HB"] = dissect_heartbeat,
    ["DN"] = dissect_disconnect
}

-- Invoke the body dissector for the given encoding type
local function dissect_body(encoding, buffer, pinfo, tree)
    body_dissectors[encoding](buffer, pinfo, tree)
end

-- List of BTP fields
btp_proto.fields = {
    protocol_id, version, sequence_id, body_encoding, body_length, message_type,
    product_id, disconnect_reason, expected_sequence_id, actual_sequence_id,
    connection_id, auth_token, heartbeat_interval, persist_orders,
    login_reject_reason, market_state, ack_id, side, price, quantity,
    bids_length, bid_levels, asks_length, ask_levels, order_id, account_id_len,
    account_id, cti_type, firm_name_len, firm_name, firm_type, user_memo_len,
    user_memo, modify_id, old_price, old_quantity, filled_quantity, liquidity,
    close_reason, order_entry_reject_reason, time_in_force
}

-- This function dissects BTP packets
function btp_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 12 then -- ignore packets that are less than 12 bytes
        return
    end

    pinfo.cols.protocol = btp_proto.name

    -- dissect header
    local subtree = tree:add(btp_proto, buffer:range(),
                             "Bitnomial Trading Protocol")
    local header = subtree:add_le(btp_proto, buffer:range(0, 12), "BTP Header")
    header:add_le(protocol_id, buffer:range(0, 2))
    header:add_le(version, buffer:range(2, 2))
    header:add_le(sequence_id, buffer:range(4, 4))
    header:add_le(body_encoding, buffer:range(8, 2))
    header:add_le(body_length, buffer:range(10, 2))

    -- dissect body based on the encoding
    local body = subtree:add_le(btp_proto, buffer:range(12), "BTP Body")
    local encoding = buffer:range(8, 2):string()
    dissect_body(encoding, buffer:range(12), pinfo, body)
end

-- This function matches packets against a series of tests to determine whether
-- or not the packet is a BTP packet
local function heuristic_checker(buffer, pinfo, tree)
    -- ensure that we have at least the minimum packet size
    local length = buffer:len()
    if length < 12 then return false end

    -- ensure that the protocol ID matches
    local protocol = buffer:range(0, 2):string()
    if protocol ~= "BT" then return false end

    -- ensure that the protocol version is version 2
    local version = buffer:range(2, 2):le_uint()
    if version ~= 0x0002 then return false end

    -- ensure that the body encoding is valid
    local encoding = buffer:range(8, 2):string()
    if body_dissectors[encoding] == nil then return false end

    -- invoke dissector
    btp_proto.dissector(buffer, pinfo, tree)
    return true
end

-- register our heuristic checker
btp_proto:register_heuristic("tcp", heuristic_checker)
