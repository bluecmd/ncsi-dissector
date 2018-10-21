/* packet-ncsi.c
 * Routines for NCSI packet disassembly (DMTF DSP0222)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * By Christian Svensson <bluecmd@google.com
 * Copyright 2018 Google Inc
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/etypes.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define NCSI_PKT_OEM_REQ  0x50
#define NCSI_PKT_OEM_RESP NCSI_PKT_OEM_REQ + 128

void proto_register_ncsi(void);

static int proto_ncsi = -1;

static int hf_ncsi_mc_id = -1;
static int hf_ncsi_header_rev = -1;
static int hf_ncsi_iid = -1;
static int hf_ncsi_ctrl_pkt_type = -1;
static int hf_ncsi_ch_id = -1;
static int hf_ncsi_payload_len = -1;
static int hf_ncsi_cmd_response = -1;
static int hf_ncsi_cmd_reason = -1;
static int hf_ncsi_cmd_oem_req = -1;
static int hf_ncsi_cmd_oem_resp = -1;
static int hf_ncsi_oem_mid = -1;
static int hf_ncsi_oem_vdata = -1;

static gint ett_ncsi = -1;
static gint ett_ncsi_cmd = -1;

static dissector_handle_t ncsi_handle;
static dissector_table_t ncsi_cmd_table;

static expert_field ei_ncsi_cmd_unknown = EI_INIT;

static int
dissect_ncsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint32 offset = 0;
  guint32 cmd = 0;
  guint32 plen = 0;
  dissector_handle_t cmd_handle;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCSI");
  col_clear(pinfo->cinfo, COL_INFO);

  proto_item *ti = proto_tree_add_item(tree, proto_ncsi, tvb, 0, -1, ENC_NA);
  proto_tree *ncsi_tree = proto_item_add_subtree(ti, ett_ncsi);
  proto_tree_add_item(ncsi_tree, hf_ncsi_mc_id, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ncsi_tree, hf_ncsi_header_rev, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ncsi_tree, hf_ncsi_iid, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(ncsi_tree, hf_ncsi_ctrl_pkt_type, tvb, 4, 1, ENC_BIG_ENDIAN, &cmd);
  proto_tree_add_item(ncsi_tree, hf_ncsi_ch_id, tvb, 5, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(ncsi_tree, hf_ncsi_payload_len, tvb, 6, 2, ENC_BIG_ENDIAN, &plen);

  offset = 16;

  if (cmd > 128) {
    // Decode command response/reason that are present on all responses
    proto_tree_add_item(ncsi_tree, hf_ncsi_cmd_response, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncsi_tree, hf_ncsi_cmd_reason, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    offset += 4;
  }

  cmd_handle = dissector_get_uint_handle(ncsi_cmd_table, cmd);
  if (cmd_handle != NULL)
  {
    tvbuff_t *tvb_sub;
    tvb_sub = tvb_new_subset_length(tvb, offset, plen);
    offset += call_dissector(cmd_handle, tvb_sub, pinfo, tree);
  }
  else
  {
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "[unknown command]");
    expert_add_info(pinfo, ti, &ei_ncsi_cmd_unknown);
  }
  return offset;
}

void
proto_register_ncsi(void)
{
  static hf_register_info hf[] = {
    { &hf_ncsi_mc_id,
      { "MC ID", "ncsi.mc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_header_rev,
      { "Header Revision", "ncsi.hdr_rev", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_iid,
      { "Instance ID", "ncsi.iid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_ctrl_pkt_type,
      { "Control Packet Type", "ncsi.ctrl_pkt_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_ch_id,
      { "Channel ID", "ncsi.ch_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_payload_len,
      { "Payload Length", "ncsi.payload_len", FT_UINT16, BASE_DEC, NULL, 0xfff, NULL, HFILL }
    },
    { &hf_ncsi_cmd_response,
      { "Response Code", "ncsi.response", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_reason,
      { "Reason Code", "ncsi.reason", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_oem_req,
      { "OEM Request", "ncsi.oem_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_cmd_oem_resp,
      { "OEM Response", "ncsi.oem_resp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_oem_mid,
      { "Manufacturer ID", "ncsi.oem.mid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ncsi_oem_vdata,
      { "Vendor data", "ncsi.oem.vendor_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
  };

  static gint *ett[] = {&ett_ncsi, &ett_ncsi_cmd};

  static ei_register_info ei[] = {
     { &ei_ncsi_cmd_unknown, { "ncsi.cmd_unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
  };

  proto_ncsi = proto_register_protocol("Network Controller Sideband Interface",
                                       "NCSI", "ncsi");
  proto_register_field_array(proto_ncsi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_module_t* expert_ncsi;
  expert_ncsi = expert_register_protocol(proto_ncsi);
  expert_register_field_array(expert_ncsi, ei, array_length(ei));

  ncsi_cmd_table = register_dissector_table("ncsi.ctrl_pkt_type", "NCSI Command", proto_ncsi, FT_UINT8, BASE_NONE);
  ncsi_handle = register_dissector("ncsi" , dissect_ncsi, proto_ncsi);
}

static int
dissect_ncsi_oem_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "OEM response");
  ti = proto_tree_add_item(tree, hf_ncsi_cmd_oem_resp, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ncsi_cmd);

  proto_tree_add_item(tree, hf_ncsi_oem_mid, tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_ncsi_oem_vdata, tvb, 4,
                      tvb_captured_length(tvb) - 4, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_oem_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  proto_item *ti;
  col_append_str(pinfo->cinfo, COL_INFO, "OEM request");
  ti = proto_tree_add_item(tree, hf_ncsi_cmd_oem_req, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_ncsi_cmd);
  proto_tree_add_item(tree, hf_ncsi_oem_mid, tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_ncsi_oem_vdata, tvb, 4,
                      tvb_captured_length(tvb) - 4, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

void
proto_reg_handoff_ncsi(void)
{
  dissector_handle_t command_handle;
  dissector_add_uint("ethertype", ETHERTYPE_NCSI, ncsi_handle);

  command_handle = create_dissector_handle(dissect_ncsi_oem_resp, proto_ncsi);
  dissector_add_uint("ncsi.ctrl_pkt_type", NCSI_PKT_OEM_RESP, command_handle);
  command_handle = create_dissector_handle(dissect_ncsi_oem_req, proto_ncsi);
  dissector_add_uint("ncsi.ctrl_pkt_type", NCSI_PKT_OEM_REQ, command_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
