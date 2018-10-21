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

#define NCSI_CMD_CIS   0x00
#define NCSI_CMD_SP    0x01
#define NCSI_CMD_DP    0x02
#define NCSI_CMD_EC    0x03
#define NCSI_CMD_DC    0x04
#define NCSI_CMD_RC    0x05
#define NCSI_CMD_ECNTX 0x06
#define NCSI_CMD_DCNTX 0x07
#define NCSI_CMD_AEN   0x08
#define NCSI_CMD_SL    0x09
#define NCSI_CMD_GLS   0x0A
#define NCSI_CMD_SVF   0x0B
#define NCSI_CMD_EV    0x0C
#define NCSI_CMD_DV    0x0D
#define NCSI_CMD_SMA   0x0E
#define NCSI_CMD_EBF   0x10
#define NCSI_CMD_DBF   0x11
#define NCSI_CMD_EGMF  0x12
#define NCSI_CMD_DGMF  0x13
#define NCSI_CMD_SFC   0x14
#define NCSI_CMD_GVID  0x15
#define NCSI_CMD_GC    0x16
#define NCSI_CMD_GP    0x17
#define NCSI_CMD_GCPS  0x18
#define NCSI_CMD_GS    0x19
#define NCSI_CMD_GPS   0x1A
#define NCSI_CMD_OEM   0x50

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

  if (cmd > 0x7f) {
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
dissect_ncsi_cis_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Clear Initial State request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_cis_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Clear Initial State response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sp_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Select Package request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sp_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Select Package response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dp_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Deselect Package request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dp_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Deselect Package response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ec_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Channel request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ec_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Channel response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dc_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Channel request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dc_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Channel response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_rc_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Reset Channel request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_rc_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Reset Channel response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ecntx_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Channel Network TX request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ecntx_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Channel Network TX response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dcntx_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Channel Network TX request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dcntx_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Channel Network TX response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_aen_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "AEN Enable request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_aen_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "AEN Enable response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sl_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set Link request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sl_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set Link response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gls_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Link Status request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gls_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Link Status response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_svf_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set VLAN Filter request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_svf_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set VLAN Filter response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ev_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable VLAN request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ev_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable VLAN response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dv_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable VLAN request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dv_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable VLAN response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sma_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set MAC dAdress request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sma_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set MAC Address response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ebf_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Broadcast Filtering request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_ebf_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Broadcast Filtering response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dbf_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Broadcast Filtering request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dbf_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Broadcast Filtering response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_egmf_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Global Multicast Filtering request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_egmf_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Enable Global Multicast Filtering response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dgmf_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Global Multicast Filtering request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_dgmf_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Disable Global Multicast Filtering response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sfc_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set NC-SI Flow Control request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_sfc_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Set NC-SI Flow Control response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gvid_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Version ID request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gvid_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Version ID response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gc_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Capabilities request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gc_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Capabilities response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gp_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Parameters request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gp_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Parameters response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gcps_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Controller Packet Statistics request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gcps_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get Controller Packet Statistics response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gs_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get NC-SI Statistics request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gs_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get NC-SI Statistics response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gps_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get NC-SI Pass-through Statistics request");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
}

static int
dissect_ncsi_gps_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  col_append_str(pinfo->cinfo, COL_INFO, "Get NC-SI Pass-through Statistics response");
  /* TODO(bluecmd): Implement */
  return tvb_captured_length(tvb);
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

static void
reg_ncsi_cmd(guint32 cmd, dissector_t req, dissector_t resp)
{
  dissector_handle_t command_handle;
  command_handle = create_dissector_handle(req, proto_ncsi);
  dissector_add_uint("ncsi.ctrl_pkt_type", cmd, command_handle);
  command_handle = create_dissector_handle(resp, proto_ncsi);
  dissector_add_uint("ncsi.ctrl_pkt_type", cmd + 0x80, command_handle);
}

void
proto_reg_handoff_ncsi(void)
{
  dissector_add_uint("ethertype", ETHERTYPE_NCSI, ncsi_handle);

  reg_ncsi_cmd(NCSI_CMD_CIS, dissect_ncsi_cis_req, dissect_ncsi_cis_resp);
  reg_ncsi_cmd(NCSI_CMD_SP, dissect_ncsi_sp_req, dissect_ncsi_sp_resp);
  reg_ncsi_cmd(NCSI_CMD_DP, dissect_ncsi_dp_req, dissect_ncsi_dp_resp);
  reg_ncsi_cmd(NCSI_CMD_EC, dissect_ncsi_ec_req, dissect_ncsi_ec_resp);
  reg_ncsi_cmd(NCSI_CMD_DC, dissect_ncsi_dc_req, dissect_ncsi_dc_resp);
  reg_ncsi_cmd(NCSI_CMD_RC, dissect_ncsi_rc_req, dissect_ncsi_rc_resp);
  reg_ncsi_cmd(NCSI_CMD_ECNTX, dissect_ncsi_ecntx_req, dissect_ncsi_ecntx_resp);
  reg_ncsi_cmd(NCSI_CMD_DCNTX, dissect_ncsi_dcntx_req, dissect_ncsi_dcntx_resp);
  reg_ncsi_cmd(NCSI_CMD_AEN, dissect_ncsi_aen_req, dissect_ncsi_aen_resp);
  reg_ncsi_cmd(NCSI_CMD_SL, dissect_ncsi_sl_req, dissect_ncsi_sl_resp);
  reg_ncsi_cmd(NCSI_CMD_GLS, dissect_ncsi_gls_req, dissect_ncsi_gls_resp);
  reg_ncsi_cmd(NCSI_CMD_SVF, dissect_ncsi_svf_req, dissect_ncsi_svf_resp);
  reg_ncsi_cmd(NCSI_CMD_EV, dissect_ncsi_ev_req, dissect_ncsi_ev_resp);
  reg_ncsi_cmd(NCSI_CMD_DV, dissect_ncsi_dv_req, dissect_ncsi_dv_resp);
  reg_ncsi_cmd(NCSI_CMD_SMA, dissect_ncsi_sma_req, dissect_ncsi_sma_resp);
  reg_ncsi_cmd(NCSI_CMD_EBF, dissect_ncsi_ebf_req, dissect_ncsi_ebf_resp);
  reg_ncsi_cmd(NCSI_CMD_DBF, dissect_ncsi_dbf_req, dissect_ncsi_dbf_resp);
  reg_ncsi_cmd(NCSI_CMD_EGMF, dissect_ncsi_egmf_req, dissect_ncsi_egmf_resp);
  reg_ncsi_cmd(NCSI_CMD_DGMF, dissect_ncsi_dgmf_req, dissect_ncsi_dgmf_resp);
  reg_ncsi_cmd(NCSI_CMD_SFC, dissect_ncsi_sfc_req, dissect_ncsi_sfc_resp);
  reg_ncsi_cmd(NCSI_CMD_GVID, dissect_ncsi_gvid_req, dissect_ncsi_gvid_resp);
  reg_ncsi_cmd(NCSI_CMD_GC, dissect_ncsi_gc_req, dissect_ncsi_gc_resp);
  reg_ncsi_cmd(NCSI_CMD_GP, dissect_ncsi_gp_req, dissect_ncsi_gp_resp);
  reg_ncsi_cmd(NCSI_CMD_GCPS, dissect_ncsi_gcps_req, dissect_ncsi_gcps_resp);
  reg_ncsi_cmd(NCSI_CMD_GS, dissect_ncsi_gs_req, dissect_ncsi_gs_resp);
  reg_ncsi_cmd(NCSI_CMD_GPS, dissect_ncsi_gps_req, dissect_ncsi_gps_resp);
  reg_ncsi_cmd(NCSI_CMD_OEM, dissect_ncsi_oem_req, dissect_ncsi_oem_resp);
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
