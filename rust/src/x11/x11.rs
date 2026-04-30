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

//! X11 app-layer state machine.
//!
//! Implements connection state tracking, transaction management,
//! and FFI callbacks for Suricata's application layer framework.
//! Uses a single-transaction-per-connection model.

use super::parser::{
    self, X11ByteOrder, X11ServerMessage, X11SetupRequest, X11SetupResponse,
};
use crate::applayer::*;
use crate::core::{ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::flow::Flow;
use nom7 as nom;
use std;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(super) static mut ALPROTO_X11: AppProto = ALPROTO_UNKNOWN;

/// X11 连接状态机
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum X11ConnState {
    #[default]
    Idle,      // 初始状态，等待客户端 Setup Request
    Setup,     // 已收到 Setup Request，等待服务器 Setup Response
    Connected, // 连接建立完成，正常数据交换
    Closed,    // 连接已关闭
}

/// 应用层事件
#[derive(AppLayerEvent)]
pub enum X11Event {
    MalformedData,        // 解析失败
    AuthenticationFailed, // 服务器拒绝认证
}

/// X11 错误记录（去重）
#[derive(Debug, Clone)]
pub struct X11ErrorRecord {
    pub code: u8,
    pub name: &'static str,
}

/// X11 事务 — 整连接单事务模型
pub struct X11Transaction {
    pub tx_id: u64,
    pub done: bool,

    // Phase 1: setup 信息
    pub setup_request: Option<X11SetupRequest>,
    pub setup_response: Option<X11SetupResponse>,
    pub version_string: String, // "11.0" 用于 sticky buffer

    // Phase 2: 请求/响应统计
    pub request_total_count: u64,
    pub request_opcodes: HashMap<&'static str, u64>,
    pub reply_count: u64,
    pub event_count: u64,
    pub error_count: u64,
    pub errors: Vec<X11ErrorRecord>,
    pub error_codes_seen: HashSet<u8>,

    tx_data: AppLayerTxData,
}

impl Default for X11Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl X11Transaction {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            done: false,
            setup_request: None,
            setup_response: None,
            version_string: String::new(),
            request_total_count: 0,
            request_opcodes: HashMap::new(),
            reply_count: 0,
            event_count: 0,
            error_count: 0,
            errors: Vec::new(),
            error_codes_seen: HashSet::new(),
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for X11Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

/// X11 应用层状态
#[derive(Default)]
pub struct X11State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<X11Transaction>,
    pub conn_state: X11ConnState,
    pub byte_order: Option<X11ByteOrder>,
    ts_buf: Vec<u8>, // 客户端方向 TCP 流缓冲
    tc_buf: Vec<u8>, // 服务器方向 TCP 流缓冲
    request_gap: bool,
    response_gap: bool,
}

impl State<X11Transaction> for X11State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&X11Transaction> {
        self.transactions.get(index)
    }
}

impl X11State {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&X11Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> X11Transaction {
        let mut tx = X11Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx
    }

    /// 获取或创建当前连接的唯一事务
    fn get_or_create_tx(&mut self) -> &mut X11Transaction {
        if self.transactions.is_empty() {
            let tx = self.new_tx();
            self.transactions.push_back(tx);
        }
        self.transactions.back_mut().unwrap()
    }

    /// 标记连接关闭
    fn mark_done(&mut self) {
        if let Some(tx) = self.transactions.back_mut() {
            tx.done = true;
        }
    }

    /// 解析客户端方向数据
    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // 如果之前有 gap，直到能重新探测到 X11 协议边界之前忽略数据
        if self.request_gap {
            // 在 Connected 状态下无法可靠恢复（没有外层帧协议），直接忽略
            return AppLayerResult::ok();
        }

        let buf = if !self.ts_buf.is_empty() {
            self.ts_buf.extend_from_slice(input);
            std::mem::take(&mut self.ts_buf)
        } else {
            input.to_vec()
        };

        let result = self.parse_request_inner(&buf);
        match result {
            Ok(consumed) => {
                if consumed < buf.len() {
                    self.ts_buf = buf[consumed..].to_vec();
                }
                AppLayerResult::ok()
            }
            Err(ParseError::Incomplete) => {
                self.ts_buf = buf;
                AppLayerResult::ok()
            }
            Err(ParseError::Error) => {
                AppLayerResult::err()
            }
        }
    }

    fn parse_request_inner(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        match self.conn_state {
            X11ConnState::Idle => {
                // 期望 Setup Request
                match parser::parse_setup_request(input) {
                    Ok((rem, req)) => {
                        let consumed = input.len() - rem.len();
                        self.byte_order = Some(req.byte_order);

                        let version = format!("{}.{}", req.major_version, req.minor_version);
                        let tx = self.get_or_create_tx();
                        tx.version_string = version;
                        tx.setup_request = Some(req);
                        tx.tx_data.updated_ts = true;

                        self.conn_state = X11ConnState::Setup;
                        Ok(consumed)
                    }
                    Err(nom::Err::Incomplete(_)) => Err(ParseError::Incomplete),
                    Err(_) => {
                        let tx = self.get_or_create_tx();
                        tx.tx_data.set_event(X11Event::MalformedData as u8);
                        Err(ParseError::Error)
                    }
                }
            }
            X11ConnState::Connected => {
                // Phase 2: 解析请求头并统计
                self.parse_requests_connected(input)
            }
            _ => {
                // Setup 或 Closed 状态下客户端不应有新数据
                Ok(input.len())
            }
        }
    }

    /// Connected 状态下循环解析请求头，累加统计
    fn parse_requests_connected(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        let byte_order = match self.byte_order {
            Some(bo) => bo,
            None => return Err(ParseError::Error),
        };

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_request_header(start, byte_order) {
                Ok((rem, hdr)) => {
                    let tx = self.get_or_create_tx();
                    tx.request_total_count += 1;
                    let name = parser::opcode_name(hdr.opcode);
                    *tx.request_opcodes.entry(name).or_insert(0) += 1;
                    start = rem;
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Save remaining for next call
                    self.ts_buf = start.to_vec();
                    return Ok(input.len()); // we handled the buffering ourselves
                }
                Err(_) => {
                    let tx = self.get_or_create_tx();
                    tx.tx_data.set_event(X11Event::MalformedData as u8);
                    return Err(ParseError::Error);
                }
            }
        }
        Ok(input.len())
    }

    /// 解析服务器方向数据
    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            return AppLayerResult::ok();
        }

        let buf = if !self.tc_buf.is_empty() {
            self.tc_buf.extend_from_slice(input);
            std::mem::take(&mut self.tc_buf)
        } else {
            input.to_vec()
        };

        let result = self.parse_response_inner(&buf);
        match result {
            Ok(consumed) => {
                if consumed < buf.len() {
                    self.tc_buf = buf[consumed..].to_vec();
                }
                AppLayerResult::ok()
            }
            Err(ParseError::Incomplete) => {
                self.tc_buf = buf;
                AppLayerResult::ok()
            }
            Err(ParseError::Error) => {
                AppLayerResult::err()
            }
        }
    }

    fn parse_response_inner(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        match self.conn_state {
            X11ConnState::Setup => {
                // 期望 Setup Response
                let byte_order = match self.byte_order {
                    Some(bo) => bo,
                    None => return Err(ParseError::Error),
                };

                match parser::parse_setup_response(input, byte_order) {
                    Ok((rem, resp)) => {
                        let consumed = input.len() - rem.len();

                        // Determine new state and events based on response
                        let (new_state, auth_failed, mark_done) = match &resp {
                            X11SetupResponse::Success { .. } => {
                                (X11ConnState::Connected, false, false)
                            }
                            X11SetupResponse::Failed { .. } => {
                                (X11ConnState::Closed, true, true)
                            }
                            X11SetupResponse::Authenticate { .. } => {
                                (X11ConnState::Closed, true, true)
                            }
                        };

                        self.conn_state = new_state;

                        let tx = self.get_or_create_tx();
                        tx.tx_data.updated_tc = true;
                        if auth_failed {
                            tx.tx_data.set_event(X11Event::AuthenticationFailed as u8);
                        }
                        if mark_done {
                            tx.done = true;
                        }
                        tx.setup_response = Some(resp);
                        Ok(consumed)
                    }
                    Err(nom::Err::Incomplete(_)) => Err(ParseError::Incomplete),
                    Err(_) => {
                        let tx = self.get_or_create_tx();
                        tx.tx_data.set_event(X11Event::MalformedData as u8);
                        Err(ParseError::Error)
                    }
                }
            }
            X11ConnState::Connected => {
                // Phase 2: 解析服务器消息（Reply/Error/Event）
                self.parse_responses_connected(input)
            }
            _ => {
                Ok(input.len())
            }
        }
    }

    /// Connected 状态下循环解析服务器消息
    fn parse_responses_connected(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        let byte_order = match self.byte_order {
            Some(bo) => bo,
            None => return Err(ParseError::Error),
        };

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_server_message(start, byte_order) {
                Ok((rem, msg)) => {
                    let tx = self.get_or_create_tx();
                    match msg {
                        X11ServerMessage::Reply { .. } => {
                            tx.reply_count += 1;
                        }
                        X11ServerMessage::Event { .. } => {
                            tx.event_count += 1;
                        }
                        X11ServerMessage::Error { code, .. } => {
                            tx.error_count += 1;
                            if !tx.error_codes_seen.contains(&code) {
                                tx.error_codes_seen.insert(code);
                                tx.errors.push(X11ErrorRecord {
                                    code,
                                    name: parser::error_code_name(code),
                                });
                            }
                        }
                    }
                    start = rem;
                }
                Err(nom::Err::Incomplete(_)) => {
                    self.tc_buf = start.to_vec();
                    return Ok(input.len());
                }
                Err(_) => {
                    let tx = self.get_or_create_tx();
                    tx.tx_data.set_event(X11Event::MalformedData as u8);
                    return Err(ParseError::Error);
                }
            }
        }
        Ok(input.len())
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
        self.ts_buf.clear();
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
        self.tc_buf.clear();
    }
}

enum ParseError {
    Incomplete,
    Error,
}

// ===== C FFI exports =====

unsafe extern "C" fn x11_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 12 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if parser::probe_x11(slice) {
            return ALPROTO_X11;
        }
    }
    ALPROTO_UNKNOWN
}

extern "C" fn x11_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = X11State::new();
    let boxed = Box::new(state);
    Box::into_raw(boxed) as *mut c_void
}

unsafe extern "C" fn x11_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut X11State));
}

unsafe extern "C" fn x11_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, X11State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn x11_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    let state = cast_pointer!(state, X11State);

    if eof {
        state.mark_done();
        return AppLayerResult::ok();
    }

    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        return AppLayerResult::ok();
    }

    let buf = stream_slice.as_slice();
    state.parse_request(buf)
}

unsafe extern "C" fn x11_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, X11State);

    if eof {
        state.mark_done();
        return AppLayerResult::ok();
    }

    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
        return AppLayerResult::ok();
    }

    let buf = stream_slice.as_slice();
    state.parse_response(buf)
}

unsafe extern "C" fn x11_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, X11State);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn x11_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, X11State);
    state.tx_id
}

unsafe extern "C" fn x11_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, X11Transaction);
    if tx.done {
        return 1;
    }
    0
}

export_tx_data_get!(x11_get_tx_data, X11Transaction);
export_state_data_get!(x11_get_state_data, X11State);

const PARSER_NAME: &[u8] = b"x11\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterX11Parser() {
    let default_port = CString::new("[6000:6063]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(x11_probing_parser),
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: x11_state_new,
        state_free: x11_state_free,
        tx_free: x11_state_tx_free,
        parse_ts: x11_parse_request,
        parse_tc: x11_parse_response,
        get_tx_count: x11_state_get_tx_count,
        get_tx: x11_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: x11_tx_get_alstate_progress,
        get_eventinfo: Some(X11Event::get_event_info),
        get_eventinfo_byid: Some(X11Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<X11State, X11Transaction>),
        get_tx_data: x11_get_tx_data,
        get_state_data: x11_get_state_data,
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
        ALPROTO_X11 = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_X11);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个大端序无认证的 Setup Request
    fn make_setup_request_be() -> Vec<u8> {
        vec![
            0x42, 0x00, // byte_order='B', unused
            0x00, 0x0B, // major=11 (BE)
            0x00, 0x00, // minor=0 (BE)
            0x00, 0x00, // auth_name_len=0
            0x00, 0x00, // auth_data_len=0
            0x00, 0x00, // unused
        ]
    }

    /// 构造一个小端序无认证的 Setup Request
    fn make_setup_request_le() -> Vec<u8> {
        vec![
            0x6c, 0x00, // byte_order='l', unused
            0x0B, 0x00, // major=11 (LE)
            0x00, 0x00, // minor=0 (LE)
            0x00, 0x00, // auth_name_len=0
            0x00, 0x00, // auth_data_len=0
            0x00, 0x00, // unused
        ]
    }

    /// 构造一个小端序 Success Setup Response
    fn make_setup_response_success_le() -> Vec<u8> {
        let vendor = b"TestVendor"; // 10 bytes
        let vendor_pad = parser::pad4(vendor.len()); // 2
        let additional_words = (32 + vendor.len() + vendor_pad) / 4; // 11

        let mut buf = vec![1, 0]; // status=Success, unused
        buf.extend_from_slice(&11u16.to_le_bytes()); // major
        buf.extend_from_slice(&0u16.to_le_bytes());  // minor
        buf.extend_from_slice(&(additional_words as u16).to_le_bytes());

        // 32-byte fixed additional data
        buf.extend_from_slice(&12101004u32.to_le_bytes()); // release_number
        buf.extend_from_slice(&0u32.to_le_bytes());        // resource_id_base
        buf.extend_from_slice(&0x001FFFFFu32.to_le_bytes()); // resource_id_mask
        buf.extend_from_slice(&256u32.to_le_bytes());       // motion_buffer_size
        buf.extend_from_slice(&(vendor.len() as u16).to_le_bytes()); // vendor_len
        buf.extend_from_slice(&65535u16.to_le_bytes());     // max_request_len
        buf.push(1);  // screen_count
        buf.push(0);  // format_count
        buf.push(0);  // image_byte_order
        buf.push(0);  // bitmap_format_bit_order
        buf.push(32); // bitmap_format_scanline_unit
        buf.push(32); // bitmap_format_scanline_pad
        buf.push(8);  // min_keycode
        buf.push(255);// max_keycode
        buf.extend_from_slice(&[0u8; 4]); // unused (4 bytes)

        buf.extend_from_slice(vendor);
        buf.extend_from_slice(&vec![0u8; vendor_pad]);
        buf
    }

    /// 构造一个大端序 Failed Setup Response
    fn make_setup_response_failed_be() -> Vec<u8> {
        let reason = b"No auth";
        let reason_pad = parser::pad4(reason.len()); // 1
        let additional_words = (reason.len() + reason_pad) / 4; // 2

        let mut buf = vec![0, reason.len() as u8]; // status=Failed, reason_len
        buf.extend_from_slice(&11u16.to_be_bytes()); // major
        buf.extend_from_slice(&0u16.to_be_bytes());  // minor
        buf.extend_from_slice(&(additional_words as u16).to_be_bytes());
        buf.extend_from_slice(reason);
        buf.extend_from_slice(&vec![0u8; reason_pad]);
        buf
    }

    #[test]
    fn test_state_machine_normal_flow() {
        let mut state = X11State::new();
        assert_eq!(state.conn_state, X11ConnState::Idle);

        // Client sends Setup Request (little-endian)
        let req = make_setup_request_le();
        let result = state.parse_request(&req);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.conn_state, X11ConnState::Setup);
        assert_eq!(state.byte_order, Some(X11ByteOrder::LittleEndian));

        // Server sends Setup Response (success)
        let resp = make_setup_response_success_le();
        let result = state.parse_response(&resp);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.conn_state, X11ConnState::Connected);

        // Verify transaction
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(!tx.done);
        assert_eq!(tx.version_string, "11.0");
        assert!(tx.setup_request.is_some());
        assert!(tx.setup_response.is_some());
    }

    #[test]
    fn test_state_machine_auth_failed() {
        let mut state = X11State::new();

        // Client sends Setup Request (big-endian)
        let req = make_setup_request_be();
        state.parse_request(&req);
        assert_eq!(state.conn_state, X11ConnState::Setup);

        // Server sends Failed Response
        let resp = make_setup_response_failed_be();
        state.parse_response(&resp);

        assert_eq!(state.conn_state, X11ConnState::Closed);
        let tx = state.transactions.front().unwrap();
        assert!(tx.done);
    }

    #[test]
    fn test_parse_setup_request_incomplete() {
        let mut state = X11State::new();

        // Send only part of setup request (6 bytes of 12 needed)
        let partial = vec![0x6c, 0x00, 0x0B, 0x00, 0x00, 0x00];
        let result = state.parse_request(&partial);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.conn_state, X11ConnState::Idle);
        assert!(!state.ts_buf.is_empty());

        // Send remaining bytes
        let remaining = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = state.parse_request(&remaining);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.conn_state, X11ConnState::Setup);
    }

    #[test]
    fn test_error_dedup() {
        let mut state = X11State::new();

        // Setup connection first
        let req = make_setup_request_le();
        state.parse_request(&req);
        let resp = make_setup_response_success_le();
        state.parse_response(&resp);
        assert_eq!(state.conn_state, X11ConnState::Connected);

        // Simulate server sending errors

        // Build two Error messages with same code, and one with different code
        let mut errors_buf = Vec::new();
        for _ in 0..2 {
            let mut err = vec![0u8, 8u8]; // type=Error, code=BadMatch(8)
            err.extend_from_slice(&1u16.to_le_bytes()); // sequence
            err.extend_from_slice(&[0u8; 28]); // pad to 32
            errors_buf.extend_from_slice(&err);
        }
        // Different error code
        let mut err = vec![0u8, 3u8]; // type=Error, code=BadWindow(3)
        err.extend_from_slice(&2u16.to_le_bytes()); // sequence
        err.extend_from_slice(&[0u8; 28]); // pad to 32
        errors_buf.extend_from_slice(&err);

        state.parse_response(&errors_buf);

        let tx = state.transactions.front().unwrap();
        assert_eq!(tx.error_count, 3); // all 3 counted
        assert_eq!(tx.errors.len(), 2); // only 2 unique error codes
        assert_eq!(tx.errors[0].code, 8);
        assert_eq!(tx.errors[0].name, "BadMatch");
        assert_eq!(tx.errors[1].code, 3);
        assert_eq!(tx.errors[1].name, "BadWindow");
    }

    #[test]
    fn test_request_counting() {
        let mut state = X11State::new();

        // Setup connection
        let req = make_setup_request_le();
        state.parse_request(&req);
        let resp = make_setup_response_success_le();
        state.parse_response(&resp);
        assert_eq!(state.conn_state, X11ConnState::Connected);

        // Build multiple requests:
        // CreateWindow(1) x2 + MapWindow(8) x1
        let mut requests = Vec::new();

        // CreateWindow: opcode=1, length=2 (8 bytes)
        for _ in 0..2 {
            let mut r = vec![1u8, 0u8]; // opcode=1, data=0
            r.extend_from_slice(&2u16.to_le_bytes()); // length=2
            r.extend_from_slice(&[0u8; 4]); // remaining 4 bytes
            requests.extend_from_slice(&r);
        }
        // MapWindow: opcode=8, length=2 (8 bytes)
        let mut r = vec![8u8, 0u8];
        r.extend_from_slice(&2u16.to_le_bytes());
        r.extend_from_slice(&[0u8; 4]);
        requests.extend_from_slice(&r);

        state.parse_request(&requests);

        let tx = state.transactions.front().unwrap();
        assert_eq!(tx.request_total_count, 3);
        assert_eq!(*tx.request_opcodes.get("CreateWindow").unwrap(), 2);
        assert_eq!(*tx.request_opcodes.get("MapWindow").unwrap(), 1);
    }

    #[test]
    fn test_full_connection_flow() {
        let mut state = X11State::new();

        // 1. Setup
        let req = make_setup_request_le();
        state.parse_request(&req);
        let resp = make_setup_response_success_le();
        state.parse_response(&resp);
        assert_eq!(state.conn_state, X11ConnState::Connected);

        // 2. Some requests
        let mut requests = Vec::new();
        for opcode in [1u8, 8, 8, 16] {
            let mut r = vec![opcode, 0u8];
            r.extend_from_slice(&2u16.to_le_bytes());
            r.extend_from_slice(&[0u8; 4]);
            requests.extend_from_slice(&r);
        }
        state.parse_request(&requests);

        // 3. Some responses
        let mut responses = Vec::new();
        // 2 Replies
        for seq in 0u16..2 {
            let mut r = vec![1u8, 0u8]; // Reply
            r.extend_from_slice(&seq.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes()); // length=0
            r.extend_from_slice(&[0u8; 24]);
            responses.extend_from_slice(&r);
        }
        // 1 Event
        let mut e = vec![2u8, 0u8]; // KeyPress
        e.extend_from_slice(&1u16.to_le_bytes());
        e.extend_from_slice(&[0u8; 28]);
        responses.extend_from_slice(&e);

        state.parse_response(&responses);

        let tx = state.transactions.front().unwrap();
        assert_eq!(tx.request_total_count, 4);
        assert_eq!(tx.reply_count, 2);
        assert_eq!(tx.event_count, 1);
        assert_eq!(tx.error_count, 0);
        assert!(!tx.done);

        assert_eq!(tx.version_string, "11.0");
    }
}
