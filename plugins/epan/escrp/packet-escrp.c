#include "config.h"
#include <epan/packet.h>
#include <assert.h>
#include <epan/expert.h>

#include "remote-port-proto.h"

// protocol item handles
static int hf_escrp_cookie;
static int hf_escrp_version;
static int hf_escrp_info;
static int hf_escrp_ticks;
static int hf_escrp_description;
// virtual fields
static int hf_escrp_name;
static int hf_escrp_source;
static int hf_escrp_destination;


static int hf_scrp_hdr;
static int hf_scrp_hdr_cmd;
static int hf_scrp_hdr_len;
static int hf_scrp_hdr_id;
static int hf_scrp_hdr_flags;
static int hf_scrp_hdr_dev;

static int hf_scrp_hello;
static int hf_scrp_hello_version;
static int hf_scrp_hello_caps_hdr;
static int hf_scrp_hello_caps_offset;
static int hf_scrp_hello_caps_len;
static int hf_scrp_hello_caps_reserved0;
static int hf_scrp_hello_caps_list;
static int hf_scrp_hello_caps_entry;

static int hf_scrp_interrupt;
static int hf_scrp_interrupt_timestamp;
static int hf_scrp_interrupt_vector;
static int hf_scrp_interrupt_line;
static int hf_scrp_interrupt_val;

static int hf_scrp_sync;
static int hf_scrp_sync_timestamp;


#define escrp_PORT 9000

// submenu handles
static int ett_escrp;
static int ett_scrp;
static int ett_scrp_hdr;
static int ett_scrp_hello;
static int ett_scrp_hello_caps_hdr;
static int ett_scrp_hello_caps_list;
static int ett_scrp_interrupt;
static int ett_scrp_sync;

static int proto_escrp;
static int proto_scrp;

static dissector_handle_t escrp_handle;

static char* scrp_cmd_name[]  __attribute__((unused))= {
    "NOP",
    "HELLO",
    "CFG",
    "READ",
    "WRITE",
    "INTERRUPT",
    "SYNC",
    "ATS_REQ",
    "ATS_INV"
};

static const value_string rp_capabilities[] = {
    { CAP_BUSACCESS_EXT_BASE, "#NewLayout" },
    { CAP_BUSACCESS_EXT_BYTE_EN, "#ByteEnables" },
    { CAP_WIRE_POSTED_UPDATES, "#PostedUpdates" },
    { CAP_ATS, "#ATS" },
    { 0, NULL }  /* must terminate with NULL */
};



static int get_name_from_path(char *buf, size_t buf_size)
{
    char *last_part = strrchr(buf, '/');
    if (last_part) {
        last_part++;  // skip the '/'
    } else {
        last_part = buf;  // no '/' found, use whole string
    }

    // Remove prefix if present
    const char *prefix = "qemu-rport-";
    const char *name;
    if (strncmp(last_part, prefix, strlen(prefix)) == 0) {
        name = last_part + strlen(prefix);
    } else {
        name = last_part;
    }

    // Copy the name to the buffer
    strncpy(buf, name, buf_size);
    buf[buf_size - 1] = '\0';  // Ensure null-termination
    return 0;
}

static int
dissect_escrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "eSCRP");

    proto_item *escrp_pdu_pi = proto_tree_add_item(tree, proto_escrp, tvb, 0, -1, ENC_NA);

    proto_tree *escrp_tree = proto_item_add_subtree(escrp_pdu_pi, ett_escrp);

    int rp_packet_offset = tvb_get_uint16(tvb, __offsetof(struct rp_mirror_pkt_hdr, rp_packet_offfset), ENC_LITTLE_ENDIAN);

    int rp_info = tvb_get_uint16(tvb, __offsetof(struct rp_mirror_pkt_hdr, info), ENC_LITTLE_ENDIAN);
    enum meta meta = (rp_info >> 1) & 0x3;
    enum direction dir = rp_info & 0x1;

    if (meta != RP_MIRROR_NONE)
    {
        proto_tree_add_string(escrp_tree, hf_escrp_source, tvb, 0, 0, "Server");
        proto_tree_add_string(escrp_tree, hf_escrp_destination, tvb, 0, 0, "");
    }
    else 
    {
        if (dir == RP_MIRROR_SEND) {
            proto_tree_add_string(escrp_tree, hf_escrp_source, tvb, 0, 0, "Server");
            proto_tree_add_string(escrp_tree, hf_escrp_destination, tvb, 0, 0, "Client");
        } else {
            proto_tree_add_string(escrp_tree, hf_escrp_source, tvb, 0, 0, "Client");
            proto_tree_add_string(escrp_tree, hf_escrp_destination, tvb, 0, 0, "Server");
        }
    }

    int offset = 0;
    proto_tree_add_item(escrp_tree, hf_escrp_cookie, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(escrp_tree, hf_escrp_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2 + 2;    // skip the rp_packet_offset field
    proto_tree_add_item(escrp_tree, hf_escrp_info, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(escrp_tree, hf_escrp_ticks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    {
        proto_tree_add_item(escrp_tree, hf_escrp_description, tvb, offset, rp_packet_offset - sizeof(struct rp_mirror_pkt_hdr), ENC_ASCII|ENC_NA);
        char buffer[256];
        tvb_get_raw_bytes_as_stringz(tvb, offset, 256, buffer);
        get_name_from_path(buffer, sizeof(buffer));
        proto_tree_add_string(escrp_tree, hf_escrp_name, tvb, 0, 0, buffer);
    }

    offset = rp_packet_offset;
    col_clear(pinfo->cinfo, COL_INFO);

    int cmd  [[maybe_unused]] = -1;
    proto_tree *scrp_tree [[maybe_unused]] = NULL;

    if (meta == RP_MIRROR_CREATE) 
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "#Create Socket");
    } 
    else if (meta == RP_MIRROR_DESTROY) 
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "#Destroy Socket");
    } 
    else 
    {    

        proto_item *scrp_pdu_pi = proto_tree_add_item(escrp_tree, proto_scrp, tvb, offset, -1, ENC_NA);
        scrp_tree = proto_item_add_subtree(scrp_pdu_pi, ett_scrp);

        proto_item *scrp_hdr_pi = proto_tree_add_none_format(scrp_tree, hf_scrp_hdr, tvb, offset, sizeof(struct rp_pkt_hdr), "Header");
        proto_tree* scrp_hdr_tree = proto_item_add_subtree(scrp_hdr_pi, ett_scrp_hdr);

        proto_tree_add_item(scrp_hdr_tree, hf_scrp_hdr_cmd, tvb, offset, 4, ENC_BIG_ENDIAN);
        cmd = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN) & 0x07; // mask to 3 bits
        offset += 4;
        proto_tree_add_item(scrp_hdr_tree, hf_scrp_hdr_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(scrp_hdr_tree, hf_scrp_hdr_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(scrp_hdr_tree, hf_scrp_hdr_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(scrp_hdr_tree, hf_scrp_hdr_dev, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", scrp_cmd_name[cmd]);

        // offset is at the begining of command specific data

        if (cmd  == RP_CMD_hello) {

            int hello_version = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            int caps_offset = rp_packet_offset + tvb_get_uint32(tvb, rp_packet_offset + __offsetof(struct rp_pkt_hello, caps), ENC_BIG_ENDIAN);
            int caps_len = tvb_get_uint16(tvb, rp_packet_offset + __offsetof(struct rp_pkt_hello, caps.len), ENC_BIG_ENDIAN);

            proto_item* hello_pi = proto_tree_add_none_format(scrp_tree, hf_scrp_hello, tvb, 
                offset, sizeof(struct rp_pkt_hello) - sizeof(struct rp_pkt_hdr) + caps_len * sizeof(uint32_t),
                 "Hello"
                );
            proto_tree* hello_tree = proto_item_add_subtree(hello_pi, ett_scrp_hello);
            col_append_fstr(pinfo->cinfo, COL_INFO, " v%u.%u", hello_version >> 16 & 0xFFFF, hello_version & 0xFFFF);
            proto_tree_add_item(hello_tree, hf_scrp_hello_version, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;


            if (caps_len > 0) 
                col_append_fstr(pinfo->cinfo, COL_INFO, " ");

            proto_item *caps_hdr_pi = proto_tree_add_none_format(hello_tree, hf_scrp_hello_caps_hdr, tvb, 
                offset, sizeof(struct rp_capabilities) + caps_len * sizeof(uint32_t), 
                "Capabilities"
             );
            proto_tree* caps_hdr_tree = proto_item_add_subtree(caps_hdr_pi, ett_scrp_hello_caps_hdr);

            proto_tree_add_item(caps_hdr_tree, hf_scrp_hello_caps_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(caps_hdr_tree, hf_scrp_hello_caps_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(caps_hdr_tree, hf_scrp_hello_caps_reserved0, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_item *caps_list_pi = proto_tree_add_none_format(caps_hdr_tree, hf_scrp_hello_caps_list, tvb, 
                caps_offset, caps_len * sizeof(uint32_t), 
                "List (%d entries)", caps_len
                );
            proto_tree* caps_list_tree = proto_item_add_subtree(caps_list_pi, ett_scrp_hello_caps_list);

            for(int i = 0; i < caps_len; i++, caps_offset +=4) {
                uint32_t cap = tvb_get_uint32(tvb, caps_offset, ENC_BIG_ENDIAN);
                const char* decoded = val_to_str_const(cap, rp_capabilities, NULL);
                if (decoded) {
                    proto_tree_add_string(caps_list_tree, hf_scrp_hello_caps_entry, tvb, caps_offset, 4, decoded);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", decoded);
                } else {
                    proto_tree_add_uint_format(caps_list_tree, hf_scrp_hello_caps_entry, tvb, 
                        caps_offset, 4, cap, 
                        "Capability unknown: %u", cap
                    );
                    col_append_fstr(pinfo->cinfo, COL_INFO, "#(%0x) ", cap);
                }
            }
        }   
        else if (cmd == RP_CMD_interrupt) {
            proto_item* interrupt_pi = proto_tree_add_none_format(scrp_tree, hf_scrp_interrupt, tvb, 
                offset, sizeof(struct rp_pkt_interrupt) - sizeof(struct rp_pkt_hdr),
                 "Interrupt"
                );
            proto_tree* interrupt_tree = proto_item_add_subtree(interrupt_pi, ett_scrp_interrupt);

            proto_tree_add_item(interrupt_tree, hf_scrp_interrupt_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            proto_tree_add_item(interrupt_tree, hf_scrp_interrupt_vector, tvb, offset, 8, ENC_BIG_ENDIAN);
            uint64_t vector = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
            offset += 8;
            proto_tree_add_item(interrupt_tree, hf_scrp_interrupt_line, tvb, offset, 4, ENC_BIG_ENDIAN);
            uint32_t line = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(interrupt_tree, hf_scrp_interrupt_val, tvb, offset, 1, ENC_BIG_ENDIAN);
            uint8_t val = tvb_get_uint8(tvb, offset);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " vector=%016llx Line[%u]=%u", vector, line, val);
        }
        else if (cmd == RP_CMD_sync) {
            proto_item* sync_pi = proto_tree_add_none_format(scrp_tree, hf_scrp_sync, tvb, 
                offset, sizeof(struct rp_pkt_sync) - sizeof(struct rp_pkt_hdr),
                 "Sync"
                );
            proto_tree* sync_tree = proto_item_add_subtree(sync_pi, ett_scrp_sync);

            proto_tree_add_item(sync_tree, hf_scrp_sync_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
        }
        else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " unknown command=%u)", cmd);
        }
    }

    return tvb_captured_length(tvb);
}


void
proto_reg_handoff_escrp(void)
{
    dissector_add_uint("udp.port", escrp_PORT, escrp_handle);
}

void
proto_register_escrp(void)
{
    static hf_register_info hf[] = {
        { &hf_escrp_cookie,
            { "cookie", "escrp.cookie",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_version,
            { "Version", "escrp.version",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_info,
            { "Info", "escrp.info",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_ticks,
            { "Ticks", "escrp.ticks",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_name,
          { "Socket Name", "escrp.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_source,
          { "Source", "escrp.source",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_destination,
            { "Destination", "escrp.destination",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_escrp_description,
            { "Socket path", "escrp.path",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        // now add the Remote Port protocol fields
        { &hf_scrp_hdr,
            { "SCRP Header", "scrp.hdr",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            "SCRP header (grouping)", HFILL }
        },        
        { &hf_scrp_hdr_cmd,
            { "Command", "scrp.cmd",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hdr_len,
            { "Length", "scrp.len",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hdr_id,
            { "ID", "scrp.id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hdr_flags,
            { "Flags", "scrp.flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hdr_dev,
            { "Device", "scrp.dev",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        // CMD HELLO fields
        { &hf_scrp_hello,
            { "SCRP Hello", "scrp.hello",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            "SCRP Hello (grouping)", HFILL }
        },        
        { &hf_scrp_hello_version,
            { "Version", "scrp.hello.version",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hello_caps_hdr,
            { "SCRP Caps hdr", "scrp.hello.caps",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            "SCRP Caps (grouping)", HFILL }
        },        
        { &hf_scrp_hello_caps_offset,
            { "Offset", "scrp.hello.caps.offset",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hello_caps_len,
            { "Len", "scrp.hello.caps.len",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hello_caps_reserved0,
            { "Reserved0", "scrp.hello.caps.reserved0",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hello_caps_list,
          { "CapabilityList", "scrp.hello.capabilities",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_hello_caps_entry,
          { "Capability", "scrp.hello.capability",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },


        // CMD INTERRUPT fields
        { &hf_scrp_interrupt,
            { "SCRP Interrupt", "scrp.interrupt",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            "SCRP Interrupt (grouping)", HFILL }
        },
        { &hf_scrp_interrupt_timestamp,
            { "Timestamp", "scrp.interrupt.timestamp",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_interrupt_vector,
            { "Vector", "scrp.interrupt.vector",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_interrupt_line,
            { "Line", "scrp.interrupt.line",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scrp_interrupt_val,
            { "Value", "scrp.interrupt.val",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        // CMD SYNC fields
        { &hf_scrp_sync,
            { "SCRP Sync", "scrp.sync",
            FT_NONE, BASE_NONE, 
            NULL, 0x0,
            "SCRP Sync (grouping)", HFILL }
        },
        { &hf_scrp_sync_timestamp,
            { "Timestamp", "scrp.sync.timestamp",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

    };

    /* Setup protocol subtrees array */
    static int *ett_escrp_submenus[] = {
        &ett_escrp,
        &ett_scrp,
        &ett_scrp_hdr,
        &ett_scrp_hello,
        &ett_scrp_hello_caps_hdr,
        &ett_scrp_hello_caps_list,
        &ett_scrp_interrupt,
    };

    proto_scrp = proto_register_protocol (
        "SystemC/TLM Remote Port Protocol", /* protocol name        */
        "scrp",          /* protocol short name  */
        "scrp"           /* protocol filter_name */
        );

    proto_escrp = proto_register_protocol (
        "Encapsulated SystemC/TLM Remote Port Protocol", /* protocol name        */
        "escrp",          /* protocol short name  */
        "escrp"           /* protocol filter_name */
        );

    proto_register_field_array(proto_escrp, hf, array_length(hf));

    proto_register_subtree_array(ett_escrp_submenus, array_length(ett_escrp_submenus));

    escrp_handle = register_dissector_with_description (
        "escrp",          /* dissector name           */
        "Encapsulated SystemC/TLM Remote Port Protocol", /* dissector description    */
        dissect_escrp,    /* dissector function       */
        proto_escrp       /* protocol being dissected */
        );

}