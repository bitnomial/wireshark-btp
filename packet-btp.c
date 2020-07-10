#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>


#define BTP_HEADER_LEN_V1 12

static int proto_btp = -1;

static int hf_btp_protocol_id = -1;
static int hf_btp_sequence_no = -1;
static int hf_btp_body_enc = -1;
static int hf_btp_version = -1;
static int hf_btp_body_len = -1;
static int hf_btp_body = -1;

static int hf_btp_body_type = -1;

static int hf_btp_body_connect_id = -1;
static int hf_btp_body_auth_token = -1;
static int hf_btp_body_reject_reason = -1;

static int hf_btp_body_market_state = -1;

static int hf_btp_body_order_id = -1;
static int hf_btp_body_product_id = -1;
static int hf_btp_body_side = -1;
static int hf_btp_body_price = -1;
static int hf_btp_body_quantity = -1;
static int hf_btp_body_time_in_force = -1;
static int hf_btp_body_modify_id = -1;
static int hf_btp_body_ack_id = -1;
static int hf_btp_body_liquidity = -1;

static int hf_btp_body_taker_side = -1;
static int hf_btp_body_last_ack_id = -1;
static int hf_btp_body_bids_length = -1;
static int hf_btp_body_asks_length = -1;
static int hf_btp_body_bids = -1;
static int hf_btp_body_asks = -1;
static int hf_btp_body_ask = -1;
static int hf_btp_body_bid = -1;

static gint ett_btp = -1;
static gint ett_btp_body = -1;
static gint ett_btp_bids = -1;
static gint ett_btp_asks = -1;
static gint ett_btp_ask = -1;
static gint ett_btp_bid = -1;


static gint
dissect_btp_header_v1(tvbuff_t * tvb, proto_tree * btp_tree, packet_info * pinfo, char * body_enc, gint offset)
{
    char proto_id[] = { tvb_get_guint8(tvb, 0), tvb_get_guint8(tvb, 1), '\0' };
    proto_tree_add_item(btp_tree, hf_btp_protocol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    guint32 seq_id = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_sequence_no, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_enc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    guint32 version = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    guint32 body_len = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_body_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_add_fstr(pinfo->cinfo, COL_INFO, "protocolId=%s sequenceId=%d bodyEncoding=%s version=%d bodyLength=%d",
                 proto_id,
                 seq_id,
                 body_enc,
                 version,
                 body_len);

    return offset;
}

static gint
dissect_btp_body_type_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    proto_tree_add_item(btp_tree, hf_btp_body_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static gint
dissect_btp_login_request_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_connect_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_auth_token, tvb, offset, 32, ENC_LITTLE_ENDIAN);
    offset += 32;

    return offset;
}

static void
add_login_reject_error_message_v1(proto_item * reason_item, guint reason_id)
{
    switch ( reason_id ) {
        case 1:
            proto_item_append_text(reason_item, " [ No request received within 1s ]");
            break;

        case 2:
            proto_item_append_text(reason_item, " [ Unauthorized ]");
            break;

        case 3:
            proto_item_append_text(reason_item, " [ Already logged in ]");
            break;

        default:
            proto_item_append_text(reason_item, " [ Unknown error message ]");
            break;
    }
}

static gint
dissect_btp_login_reject_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    guint8  reason_id = tvb_get_guint8(tvb, offset);
    proto_item * reason_item = proto_tree_add_item(btp_tree, hf_btp_body_reject_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    add_login_reject_error_message_v1(reason_item, reason_id);

    return offset;
}

static gint
dissect_btp_gw_open_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_order_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_product_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_side, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(btp_tree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_time_in_force , tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static gint
dissect_btp_gw_modify_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_order_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_modify_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static gint
dissect_btp_gw_ack_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_ack_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_order_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_modify_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static void
add_gw_reject_error_message_v1(proto_item * reason_item, guint reason_id)
{
    switch ( reason_id ) {
        case 1:
            proto_item_append_text(reason_item, " [ Order not found ]");
            break;

        case 2:
            proto_item_append_text(reason_item, " [ Order already exists ]");
            break;

        case 3:
            proto_item_append_text(reason_item, " [ Open quantity must be greater than zero to open an order ]");
            break;

        case 4:
            proto_item_append_text(reason_item, " [ Product not found ]");
            break;

        case 5:
            proto_item_append_text(reason_item, " [ Order quantity must not be greater than the max order size ]");
            break;

        case 6:
            proto_item_append_text(reason_item, " [ Order price must not be outside price bands ]");
            break;

        case 7:
            proto_item_append_text(reason_item, " [ Only close order requests are accepted while the market is halted ]");
            break;

        case 8:
            proto_item_append_text(reason_item, " [ No requests are accepted while the market is closed ]");
            break;

        case 9:
            proto_item_append_text(reason_item, " [ Account not found ]");
            break;

        case 10:
            proto_item_append_text(reason_item, " [ Give-up account not found ]");
            break;

        case 11:
            proto_item_append_text(reason_item, " [ Unauthorized give-up ]");
            break;

        case 12:
            proto_item_append_text(reason_item, " [ Modify did not change the order ]");
            break;

        default:
            proto_item_append_text(reason_item, " [ Unknown error message ]");
            break;
    }
}

static gint
dissect_btp_gw_reject_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_order_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_modify_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    guint8  reason_id = tvb_get_guint8(tvb, offset);
    proto_item * reason_item = proto_tree_add_item(btp_tree, hf_btp_body_reject_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    add_gw_reject_error_message_v1(reason_item, reason_id);

    return offset;
}

static gint
dissect_btp_gw_fill_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_ack_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_order_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_liquidity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static gint
dissect_btp_market_state_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_market_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(btp_tree, hf_btp_body_product_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static gint
dissect_btp_pf_trade_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_ack_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_product_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_taker_side, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(btp_tree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static gint
dissect_btp_pf_level_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_ack_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_product_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_side, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(btp_tree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btp_tree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static gint
dissect_btp_pf_bids_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset, guint32 bids_len)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body_bids, tvb, offset, bids_len, ENC_NA);
    proto_tree * btp_bid_tree = proto_item_add_subtree(ti, ett_btp_bids);

    gint bids_end = ((gint) bids_len) + offset;

    while ( offset < bids_end ) {
        proto_item * bid =  proto_tree_add_item(btp_bid_tree, hf_btp_body_bid, tvb, offset, 8, ENC_NA);
        proto_tree * btp_bid_subtree = proto_item_add_subtree(bid, ett_btp_bid);

        gint price = tvb_get_letohil(tvb, offset);
        guint quant = tvb_get_letohl(tvb, offset + 4);

        proto_item_append_text(bid, " %u@%d", quant, price);

        proto_tree_add_item(btp_bid_subtree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(btp_bid_subtree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static gint
dissect_btp_pf_asks_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset, guint32 asks_len)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body_asks, tvb, offset, asks_len, ENC_NA);
    proto_tree * btp_ask_tree = proto_item_add_subtree(ti, ett_btp_asks);

    gint asks_end = ((gint) asks_len) + offset;

    while ( offset < asks_end ) {
        proto_item * ask = proto_tree_add_item(btp_ask_tree, hf_btp_body_ask, tvb, offset, 8, ENC_NA);
        proto_tree * btp_ask_subtree = proto_item_add_subtree(ask, ett_btp_ask);

        gint price = tvb_get_letohil(tvb, offset);
        guint quant = tvb_get_letohl(tvb, offset + 4);

        proto_item_append_text(ask, " %u@%d", quant, price);

        proto_tree_add_item(btp_ask_subtree, hf_btp_body_price, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(btp_ask_subtree, hf_btp_body_quantity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static gint
dissect_btp_pf_book_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    offset = dissect_btp_body_type_v1(tvb, btp_tree, offset);

    proto_tree_add_item(btp_tree, hf_btp_body_last_ack_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(btp_tree, hf_btp_body_product_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    guint32 bids_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_body_bids_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // make bids subtree
    offset = dissect_btp_pf_bids_v1(tvb, btp_tree, offset, bids_len);

    guint32 asks_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_body_asks_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // make asks subtree
    offset = dissect_btp_pf_asks_v1(tvb, btp_tree, offset, asks_len);

    return offset;
}

static gint
dissect_btp_login_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body, tvb, offset, -1, ENC_NA);
    proto_tree * btp_body_tree = proto_item_add_subtree(ti, ett_btp_body);

    guint8 message_type = tvb_get_guint8(tvb, offset);

    switch (message_type) {

        case 'L':
            // Login Request

            offset = dissect_btp_login_request_v1(tvb, btp_body_tree, offset);
            break;

        case 'A':
            // Login Ack

            offset = dissect_btp_body_type_v1(tvb, btp_body_tree, offset);
            break;

        case 'R':
            // Login Reject

            offset = dissect_btp_login_reject_v1(tvb, btp_body_tree, offset);
            break;

        default:
            break;

    }

    return offset;
}

static gint
dissect_btp_gateway_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body, tvb, offset, -1, ENC_NA);
    proto_tree * btp_body_tree = proto_item_add_subtree(ti, ett_btp_body);

    guint8 message_type = tvb_get_guint8(tvb, offset);

    switch (message_type) {

        case 'O':
            // Open

            offset = dissect_btp_gw_open_v1(tvb, btp_body_tree, offset);
            break;

        case 'M':
            // Modify

            offset = dissect_btp_gw_modify_v1(tvb, btp_body_tree, offset);
            break;

        case 'A':
            // Ack

            offset = dissect_btp_gw_ack_v1(tvb, btp_body_tree, offset);
            break;

        case 'R':
            // Reject

            offset = dissect_btp_gw_reject_v1(tvb, btp_body_tree, offset);
            break;

        case 'F':
            // Fill

            offset = dissect_btp_gw_fill_v1(tvb, btp_body_tree, offset);
            break;

        case 'S':
            // Market State Protocol

            offset = dissect_btp_market_state_v1(tvb, btp_body_tree, offset);
            break;

        default:
            break;

    }

    return offset;
}

static gint
dissect_btp_drop_copy_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body, tvb, offset, -1, ENC_NA);
    proto_tree * btp_body_tree = proto_item_add_subtree(ti, ett_btp_body);

    guint8 message_type = tvb_get_guint8(tvb, offset);

    switch (message_type) {

        case 'A':
            // Ack

            offset = dissect_btp_gw_ack_v1(tvb, btp_body_tree, offset);
            break;

        case 'F':
            // Fill

            offset = dissect_btp_gw_fill_v1(tvb, btp_body_tree, offset);
            break;

        case 'S':
            // Market State Protocol

            offset = dissect_btp_market_state_v1(tvb, btp_body_tree, offset);
            break;

        default:
            break;

    }

    return offset;
}

static gint
dissect_btp_pricefeed_v1(tvbuff_t * tvb, proto_tree * btp_tree, gint offset)
{
    proto_item * ti = proto_tree_add_item(btp_tree, hf_btp_body, tvb, offset, -1, ENC_NA);
    proto_tree * btp_body_tree = proto_item_add_subtree(ti, ett_btp_body);

    guint8 message_type = tvb_get_guint8(tvb, offset);

    switch (message_type) {

        case 'T':
            // Trade

            offset = dissect_btp_pf_trade_v1(tvb, btp_body_tree, offset);
            break;

        case 'L':
            // Level

            offset = dissect_btp_pf_level_v1(tvb, btp_body_tree, offset);
            break;

        case 'B':
            // Book

            offset = dissect_btp_pf_book_v1(tvb, btp_body_tree, offset);
            break;

        case 'S':
            // Market State Protocol

            offset = dissect_btp_market_state_v1(tvb, btp_body_tree, offset);
            break;

        default:
            break;

    }

    return offset;
}

static gint
dissect_btp_v1(tvbuff_t * tvb, proto_tree * tree _U_, packet_info *pinfo)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTP");
    col_clear(pinfo->cinfo,COL_INFO);

    gint offset = 0;

    proto_item *ti = proto_tree_add_item(tree, proto_btp, tvb, 0, -1, ENC_NA);
    proto_tree *btp_tree = proto_item_add_subtree(ti, ett_btp);

    char body_enc[] = { tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7), '\0' };

    offset = dissect_btp_header_v1(tvb, btp_tree, pinfo, body_enc, offset);

    if ( strcmp(body_enc, "GW") == 0 ) {
        //Gateway Protocol

        offset = dissect_btp_gateway_v1(tvb, btp_tree, offset);
    }
    else if ( strcmp(body_enc, "PF") == 0 ) {
        //Pricefeed Protocol

        offset = dissect_btp_pricefeed_v1(tvb, btp_tree, offset);
    }
    else if ( strcmp(body_enc, "LG") == 0 ) {
        //Login Protocol

        offset = dissect_btp_login_v1(tvb, btp_tree, offset);
    }
    else if ( strcmp(body_enc, "HB") == 0 ) {
        //Heartbeat
        //Body is empty; do nothing
    }
    else if ( strcmp(body_enc, "DC") == 0 ) {
        //Drop Copy Protocol

        offset = dissect_btp_drop_copy_v1(tvb, btp_tree, offset);
    }

    return offset;
}

static gboolean
is_btp_v1(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    // Must have enough data for header values
    if ( tvb_captured_length(tvb) < BTP_HEADER_LEN_V1 ) {
        return FALSE;
    }

    // First two bytes must be 'B' and 'T'
    if ( tvb_get_guint8(tvb, 0) != 'B' ) {
        return FALSE;
    }

    if ( tvb_get_guint8(tvb, 1) != 'T' ) {
        return FALSE;
    }

    // Version must be 1
    if ( tvb_get_letohs(tvb, 8) != 1) {
        return FALSE;
    }

    return TRUE;
}


static gboolean
dissect_btp_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if ( is_btp_v1(pinfo, tvb, 0, data) ) {
        dissect_btp_v1(tvb, tree, pinfo);
        return TRUE;
    }

    return FALSE;
}

void
proto_register_btp(void)
{
    static hf_register_info hf[] = {
        { &hf_btp_protocol_id,
            { "protocolId", "btp.protocolId",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_sequence_no,
            { "sequenceId", "btp.sequenceId",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_enc,
          { "bodyEncoding", "btp.bodyEncoding",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_version,
          { "version", "btp.version",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_len,
          { "bodyLength", "btp.bodyLength",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body,
          { "Body", "btp.body",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_type,
          { "messageType", "btp.messageType",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_connect_id,
          { "connectionId", "btp.connectionId",
            FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_auth_token,
          { "authToken", "btp.authToken",
           FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_reject_reason,
          { "reason", "btp.reason",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_order_id,
          { "orderId", "btp.orderId",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_product_id,
          { "productId", "btp.productId",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_side,
          { "side", "btp.side",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_price,
          { "price", "btp.price",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_quantity,
          { "quantity", "btp.quantity",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_time_in_force,
          { "timeInForce", "btp.timeInForce",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_modify_id,
          { "modifyId", "btp.modifyId",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_ack_id,
          { "ackId", "btp.ackId",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_liquidity,
          { "liquidity", "btp.liquidity",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_market_state,
          { "marketState", "btp.marketState",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_taker_side,
          { "takerSide", "btp.takerSide",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_last_ack_id,
          { "lastAckId", "btp.lastId",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_bids_length,
          { "bidsLength", "btp.bidsLength",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_asks_length,
          { "asksLength", "btp.asksLength",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_bids,
          { "Bids", "btp.bids",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_asks,
          { "Asks", "btp.asks",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_ask,
          { "Ask", "btp.ask",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btp_body_bid,
          { "Bid", "btp.bid",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }

    };

    /* Setup protocol subtree array */
    static gint *ett[] = { &ett_btp, &ett_btp_body, &ett_btp_bids, &ett_btp_asks,
                           &ett_btp_ask, &ett_btp_bid };

    proto_btp = proto_register_protocol (
        "Bitnomial Transfer Protocol", /* name       */
        "BTP",      /* short name */
        "btp"       /* abbrev     */
        );

    proto_register_field_array(proto_btp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btp(void)
{
    heur_dissector_add("tcp", dissect_btp_heuristic, "BTP over TCP",
                       "btp_tcp", proto_btp, HEURISTIC_ENABLE);
}
