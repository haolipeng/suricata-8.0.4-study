/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! IEC 61850 MMS app-layer state machine.

use super::mms_pdu::{self, MmsPdu};
use super::parser;
use crate::applayer::*;
use crate::conf::conf_get;
use crate::core::{ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::flow::Flow;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

static mut IEC61850_MMS_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_IEC61850_MMS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum Iec61850MmsEvent {
    TooManyTransactions,
    MalformedData,
}

pub struct MmsTransaction {
    tx_id: u64,
    pub request: Option<MmsPdu>,
    pub response: Option<MmsPdu>,
    pub invoke_id: Option<u32>,

    tx_data: AppLayerTxData,
}

impl Default for MmsTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl MmsTransaction {
    pub fn new() -> MmsTransaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            invoke_id: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for MmsTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct MmsState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<MmsTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<MmsTransaction> for MmsState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&MmsTransaction> {
        self.transactions.get(index)
    }
}

impl MmsState {
    pub fn new() -> Self {
        Default::default()
    }

    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&MmsTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> MmsTransaction {
        let mut tx = MmsTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_open_request(&mut self) -> Option<&mut MmsTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn handle_mms_pdu(&mut self, pdu: MmsPdu, is_request: bool) {
        if is_request {
            let mut tx = self.new_tx();
            tx.invoke_id = pdu.invoke_id();
            tx.request = Some(pdu);
            if self.transactions.len() >= unsafe { IEC61850_MMS_MAX_TX } {
                tx.tx_data
                    .set_event(Iec61850MmsEvent::TooManyTransactions as u8);
            }
            self.transactions.push_back(tx);
        } else {
            let invoke_id = pdu.invoke_id();

            // Find the index of a matching transaction to avoid borrow issues
            let match_idx = if let Some(id) = invoke_id {
                self.transactions
                    .iter()
                    .position(|tx| tx.invoke_id == Some(id) && tx.response.is_none())
            } else {
                None
            };

            let target_idx = match_idx.or_else(|| {
                self.transactions
                    .iter()
                    .position(|tx| tx.response.is_none())
            });

            if let Some(idx) = target_idx {
                self.transactions[idx].tx_data.updated_tc = true;
                self.transactions[idx].response = Some(pdu);
            } else {
                // No matching request; create a standalone tx
                let mut tx = self.new_tx();
                tx.invoke_id = invoke_id;
                tx.tx_data.updated_tc = true;
                tx.response = Some(pdu);
                self.transactions.push_back(tx);
            }
        }
    }

    fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if is_request && self.request_gap {
            if !parser::probe_tpkt(input) {
                return AppLayerResult::ok();
            }
            self.request_gap = false;
        } else if !is_request && self.response_gap {
            if !parser::probe_tpkt(input) {
                return AppLayerResult::ok();
            }
            self.response_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_tpkt_cotp_frame(start) {
                Ok((rem, frame)) => {
                    if frame.cotp.pdu_type == parser::CotpPduType::DataTransfer
                        && !frame.payload.is_empty()
                    {
                        let mms_data = if mms_pdu::is_direct_mms_pdu(frame.payload) {
                            // Direct MMS PDU (mms-* pcap format)
                            Some(frame.payload)
                        } else {
                            // May have Session/Presentation layers (iec61850_* pcap format)
                            match mms_pdu::extract_mms_from_session(frame.payload) {
                                Ok(Some(data)) => Some(data),
                                Ok(None) => {
                                    // Session CONNECT/ACCEPT → create Initiate transaction
                                    let pdu = if is_request {
                                        MmsPdu::InitiateRequest
                                    } else {
                                        MmsPdu::InitiateResponse
                                    };
                                    self.handle_mms_pdu(pdu, is_request);
                                    None
                                }
                                Err(_) => {
                                    let mut tx = self.new_tx();
                                    tx.tx_data
                                        .set_event(Iec61850MmsEvent::MalformedData as u8);
                                    self.transactions.push_back(tx);
                                    None
                                }
                            }
                        };

                        if let Some(data) = mms_data {
                            match mms_pdu::parse_mms_pdu(data) {
                                Ok(pdu) => {
                                    self.handle_mms_pdu(pdu, is_request);
                                }
                                Err(_) => {
                                    let mut tx = self.new_tx();
                                    tx.tx_data
                                        .set_event(Iec61850MmsEvent::MalformedData as u8);
                                    self.transactions.push_back(tx);
                                }
                            }
                        }
                    } else {
                        match frame.cotp.pdu_type {
                            parser::CotpPduType::ConnectionRequest
                            | parser::CotpPduType::ConnectionConfirm => {
                                if is_request {
                                    let tx = self.new_tx();
                                    self.transactions.push_back(tx);
                                } else if let Some(tx) = self.find_open_request() {
                                    tx.tx_data.updated_tc = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    start = rem;
                    if self.transactions.len() >= unsafe { IEC61850_MMS_MAX_TX } {
                        return AppLayerResult::err();
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        self.parse_frames(input, true)
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        self.parse_frames(input, false)
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

// C exports.

unsafe extern "C" fn iec61850_mms_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 4 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if parser::probe_tpkt(slice) {
            return ALPROTO_IEC61850_MMS;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn iec61850_mms_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = MmsState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn iec61850_mms_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut MmsState));
}

unsafe extern "C" fn iec61850_mms_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, MmsState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn iec61850_mms_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, MmsState);

    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn iec61850_mms_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, MmsState);

    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn iec61850_mms_state_get_tx(
    state: *mut c_void, tx_id: u64,
) -> *mut c_void {
    let state = cast_pointer!(state, MmsState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn iec61850_mms_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, MmsState);
    return state.tx_id;
}

unsafe extern "C" fn iec61850_mms_tx_get_alstate_progress(
    tx: *mut c_void, _direction: u8,
) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);

    // Transaction is done if we have a response, or if it's a
    // one-way PDU (Conclude, Unconfirmed, etc.)
    if tx.response.is_some() {
        return 1;
    }
    // Check if this is a one-way PDU that doesn't expect a response
    if let Some(ref req) = tx.request {
        match req {
            MmsPdu::UnconfirmedPdu { .. }
            | MmsPdu::ConcludeRequest
            | MmsPdu::ConcludeResponse => {
                return 1;
            }
            _ => {}
        }
    }
    return 0;
}

export_tx_data_get!(iec61850_mms_get_tx_data, MmsTransaction);
export_state_data_get!(iec61850_mms_get_state_data, MmsState);

const PARSER_NAME: &[u8] = b"iec61850-mms\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterIec61850MmsParser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(iec61850_mms_probing_parser),
        probe_tc: Some(iec61850_mms_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: iec61850_mms_state_new,
        state_free: iec61850_mms_state_free,
        tx_free: iec61850_mms_state_tx_free,
        parse_ts: iec61850_mms_parse_request,
        parse_tc: iec61850_mms_parse_response,
        get_tx_count: iec61850_mms_state_get_tx_count,
        get_tx: iec61850_mms_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: iec61850_mms_tx_get_alstate_progress,
        get_eventinfo: Some(Iec61850MmsEvent::get_event_info),
        get_eventinfo_byid: Some(Iec61850MmsEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<MmsState, MmsTransaction>),
        get_tx_data: iec61850_mms_get_tx_data,
        get_state_data: iec61850_mms_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IEC61850_MMS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.iec61850-mms.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                IEC61850_MMS_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for iec61850-mms.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC61850_MMS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec61850mms::mms_pdu::MmsConfirmedService;

    #[test]
    fn test_parse_request_initiate() {
        let mut state = MmsState::new();
        // TPKT + COTP DT + MMS Initiate-Request
        let buf = [
            0x03, 0x00, 0x00, 0x0C, // TPKT: version=3, length=12
            0x02, 0xF0, 0x80, // COTP DT: length=2, type=0xF0, eot=0x80
            0xA8, 0x03, // MMS [8] Initiate-Request
            0x80, 0x01, 0x01, // some parameter
        ];
        let result = state.parse_request(&buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(tx.request.is_some());
        match tx.request.as_ref().unwrap() {
            MmsPdu::InitiateRequest => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_response_initiate() {
        let mut state = MmsState::new();

        // First, parse a request
        let req_buf = [
            0x03, 0x00, 0x00, 0x0C, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0xA8, 0x03, 0x80, 0x01, 0x01, // MMS Initiate-Request
        ];
        state.parse_request(&req_buf);

        // Then parse a response
        let resp_buf = [
            0x03, 0x00, 0x00, 0x0C, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0xA9, 0x03, 0x80, 0x01, 0x01, // MMS Initiate-Response
        ];
        let result = state.parse_response(&resp_buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );

        // Should have matched to the same transaction
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(tx.request.is_some());
        assert!(tx.response.is_some());
    }

    #[test]
    fn test_parse_confirmed_request_response_matching() {
        let mut state = MmsState::new();

        // Confirmed-Request with invokeID=1, Read service
        let req_buf = [
            0x03, 0x00, 0x00, 0x13, // TPKT: length=19
            0x02, 0xF0, 0x80, // COTP DT
            0xA0, 0x0A, // [0] Confirmed-Request
            0x02, 0x01, 0x01, // INTEGER invokeID=1
            0xA4, 0x05, // [4] Read
            0xA1, 0x03, 0xA0, 0x01, 0x00, // variable spec
        ];
        state.parse_request(&req_buf);
        assert_eq!(state.tx_id, 1);

        // Confirmed-Response with invokeID=1, Read service
        let resp_buf = [
            0x03, 0x00, 0x00, 0x10, // TPKT: length=16
            0x02, 0xF0, 0x80, // COTP DT
            0xA1, 0x07, // [1] Confirmed-Response
            0x02, 0x01, 0x01, // INTEGER invokeID=1
            0xA4, 0x02, 0xA1, 0x00, // [4] Read response
        ];
        state.parse_response(&resp_buf);

        // Should be matched to same tx
        assert_eq!(state.transactions.len(), 1);
        let tx = state.transactions.front().unwrap();
        assert_eq!(tx.invoke_id, Some(1));
        assert!(tx.request.is_some());
        assert!(tx.response.is_some());
        match tx.request.as_ref().unwrap() {
            MmsPdu::ConfirmedRequest { service, .. } => {
                assert_eq!(*service, MmsConfirmedService::Read);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_cotp_connection_setup() {
        let mut state = MmsState::new();

        // COTP Connection Request
        let cr_buf = [
            0x03, 0x00, 0x00, 0x0B, // TPKT: length=11
            0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0xC0, // COTP CR
        ];
        let result = state.parse_request(&cr_buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );
    }

    #[test]
    fn test_multiple_frames() {
        let mut state = MmsState::new();

        // Two TPKT frames back-to-back
        let buf = [
            // Frame 1: Initiate-Request
            0x03, 0x00, 0x00, 0x0C, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0xA8, 0x03, 0x80, 0x01, 0x01, // MMS Initiate-Request
            // Frame 2: Conclude-Request
            0x03, 0x00, 0x00, 0x09, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0xAB, 0x00, // MMS Conclude-Request
        ];
        let result = state.parse_request(&buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );
        assert_eq!(state.tx_id, 2);
    }
}
