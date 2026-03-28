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

//! IEC 60870-5-104 app-layer state machine.

use super::asdu::{self, Asdu};
use super::parser::{self, ApciFrame};
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

static mut IEC104_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_IEC104: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
pub enum Iec104Event {
    TooManyTransactions,
    MalformedApci,
    MalformedAsdu,
    InvalidTypeId,
    InvalidCot,
    InvalidApduLength,
    UnexpectedUFrame,
}

pub struct Iec104Transaction {
    pub tx_id: u64,
    pub apci: ApciFrame,
    pub asdu: Option<Asdu>,
    pub tx_data: AppLayerTxData,
}

impl Default for Iec104Transaction {
    fn default() -> Self {
        Self {
            tx_id: 0,
            apci: ApciFrame::SFrame { recv_seq: 0 },
            asdu: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for Iec104Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct Iec104State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<Iec104Transaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<Iec104Transaction> for Iec104State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&Iec104Transaction> {
        self.transactions.get(index)
    }
}

impl Iec104State {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&Iec104Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> Iec104Transaction {
        self.tx_id += 1;
        Iec104Transaction {
            tx_id: self.tx_id,
            apci: ApciFrame::SFrame { recv_seq: 0 },
            asdu: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // Handle gap recovery
        if is_request && self.request_gap {
            if !parser::probe_iec104(input) {
                return AppLayerResult::ok();
            }
            self.request_gap = false;
        } else if !is_request && self.response_gap {
            if !parser::probe_iec104(input) {
                return AppLayerResult::ok();
            }
            self.response_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_apci_frame(start) {
                Ok((rem, frame)) => {
                    let mut tx = self.new_tx();
                    tx.tx_data.updated_tc = !is_request;

                    // Validate and parse ASDU for I-frames
                    match &frame {
                        ApciFrame::IFrame { asdu_data, .. } => {
                            if !asdu_data.is_empty() {
                                match asdu::parse_asdu(asdu_data) {
                                    Ok((_, asdu)) => {
                                        // Validate TypeId
                                        if !asdu.type_id.is_valid() {
                                            tx.tx_data
                                                .set_event(Iec104Event::InvalidTypeId as u8);
                                        }
                                        // Validate COT
                                        if !asdu.cot.is_valid() {
                                            tx.tx_data
                                                .set_event(Iec104Event::InvalidCot as u8);
                                        }
                                        tx.asdu = Some(asdu);
                                    }
                                    Err(_) => {
                                        tx.tx_data
                                            .set_event(Iec104Event::MalformedAsdu as u8);
                                    }
                                }
                            }
                        }
                        ApciFrame::UFrame { function } => {
                            // Check for multiple function bits (already filtered in parser,
                            // but unknown patterns arrive here as parse errors)
                            let _ = function;
                        }
                        ApciFrame::SFrame { .. } => {}
                    }

                    tx.apci = frame;

                    if self.transactions.len() >= unsafe { IEC104_MAX_TX } {
                        tx.tx_data
                            .set_event(Iec104Event::TooManyTransactions as u8);
                    }
                    self.transactions.push_back(tx);

                    start = rem;
                    if self.transactions.len() >= unsafe { IEC104_MAX_TX } {
                        return AppLayerResult::err();
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    // Malformed APCI
                    let mut tx = self.new_tx();
                    tx.tx_data
                        .set_event(Iec104Event::MalformedApci as u8);
                    self.transactions.push_back(tx);
                    return AppLayerResult::err();
                }
            }
        }

        AppLayerResult::ok()
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

unsafe extern "C" fn iec104_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 2 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if parser::probe_iec104(slice) {
            return ALPROTO_IEC104;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn iec104_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = Iec104State::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn iec104_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut Iec104State));
}

unsafe extern "C" fn iec104_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, Iec104State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn iec104_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, Iec104State);

    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn iec104_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, Iec104State);

    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn iec104_state_get_tx(
    state: *mut c_void, tx_id: u64,
) -> *mut c_void {
    let state = cast_pointer!(state, Iec104State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn iec104_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, Iec104State);
    return state.tx_id;
}

unsafe extern "C" fn iec104_tx_get_alstate_progress(
    _tx: *mut c_void, _direction: u8,
) -> c_int {
    // IEC 104 uses per-frame transactions, always complete
    return 1;
}

export_tx_data_get!(iec104_get_tx_data, Iec104Transaction);
export_state_data_get!(iec104_get_state_data, Iec104State);

const PARSER_NAME: &[u8] = b"iec104\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterIec104Parser() {
    let default_port = CString::new("[2404]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(iec104_probing_parser),
        probe_tc: Some(iec104_probing_parser),
        min_depth: 0,
        max_depth: 6,
        state_new: iec104_state_new,
        state_free: iec104_state_free,
        tx_free: iec104_state_tx_free,
        parse_ts: iec104_parse_request,
        parse_tc: iec104_parse_response,
        get_tx_count: iec104_state_get_tx_count,
        get_tx: iec104_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: iec104_tx_get_alstate_progress,
        get_eventinfo: Some(Iec104Event::get_event_info),
        get_eventinfo_byid: Some(Iec104Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<Iec104State, Iec104Transaction>),
        get_tx_data: iec104_get_tx_data,
        get_state_data: iec104_get_state_data,
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
        ALPROTO_IEC104 = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.iec104.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                IEC104_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for iec104.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC104);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec104::parser::UFrameFunction;

    #[test]
    fn test_parse_u_frame_transaction() {
        let mut state = Iec104State::new();
        // STARTDT act
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
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
        assert_eq!(
            tx.apci,
            ApciFrame::UFrame {
                function: UFrameFunction::StartDtAct
            }
        );
        assert!(tx.asdu.is_none());
    }

    #[test]
    fn test_parse_s_frame_transaction() {
        let mut state = Iec104State::new();
        // S-frame with recv_seq=5
        let buf = [0x68, 0x04, 0x01, 0x00, 0x0A, 0x00];
        let result = state.parse_response(&buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );
        assert_eq!(state.tx_id, 1);
    }

    #[test]
    fn test_parse_i_frame_with_asdu() {
        let mut state = Iec104State::new();
        // I-frame: send_seq=0, recv_seq=0
        // ASDU: TypeID=13(M_ME_NC_1), SQ=0, num=1, COT=3, CommonAddr=1
        //       IOA=16384, float=23.5, QDS=0x00
        let buf = [
            0x68, 0x12, // start, length=18 (4 ctrl + 14 ASDU)
            0x00, 0x00, // send_seq=0
            0x00, 0x00, // recv_seq=0
            // ASDU header
            0x0D, 0x01, 0x03, 0x00, 0x01, 0x00,
            // IOA
            0x00, 0x40, 0x00,
            // float 23.5 + QDS
            0x00, 0x00, 0xBC, 0x41, 0x00,
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
        assert!(tx.asdu.is_some());
        let asdu = tx.asdu.as_ref().unwrap();
        assert_eq!(asdu.type_id, asdu::TypeId::M_ME_NC_1);
        assert_eq!(asdu.cot.cause, 3);
        assert_eq!(asdu.objects.len(), 1);
    }

    #[test]
    fn test_parse_multiple_frames() {
        let mut state = Iec104State::new();
        // Two U-frames back-to-back
        let buf = [
            0x68, 0x04, 0x07, 0x00, 0x00, 0x00, // STARTDT act
            0x68, 0x04, 0x0B, 0x00, 0x00, 0x00, // STARTDT con
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

    #[test]
    fn test_parse_incomplete_frame() {
        let mut state = Iec104State::new();
        // Incomplete - only start and length, no control fields
        let buf = [0x68, 0x04, 0x07, 0x00];
        let result = state.parse_request(&buf);
        // Should return incomplete
        assert_eq!(result.status, 1); // incomplete
    }

    #[test]
    fn test_gap_handling() {
        let mut state = Iec104State::new();
        state.on_request_gap(100);
        assert!(state.request_gap);

        // Non-IEC104 data after gap - should skip
        let buf = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = state.parse_request(&buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );

        // Valid frame after gap - should recover
        state.on_request_gap(100);
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let result = state.parse_request(&buf);
        assert_eq!(
            result,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0,
            }
        );
        assert!(!state.request_gap);
    }
}
