use crate::applayer::*;
use crate::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, *};
use crate::direction::Direction;
use crate::flow::Flow;
use nom7::Err;
use std::collections::VecDeque;
use std::ffi::CString;
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

use super::parser::{parse_mysql_greeting, parse_mysql_header, MysqlGreeting};

pub(crate) static mut ALPROTO_MYSQL: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent, Debug, PartialEq, Eq)]
enum MysqlEvent {
    MalformedGreeting,
}

#[derive(Debug)]
pub struct MysqlTransaction {
    pub tx_id: u64,
    pub greeting: Option<MysqlGreeting>,
    pub complete: bool,
    tx_data: AppLayerTxData,
}

impl Transaction for MysqlTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl MysqlTransaction {
    fn new(tx_id: u64) -> Self {
        Self {
            tx_id,
            greeting: None,
            complete: false,
            tx_data: AppLayerTxData::new(),
        }
    }
}

#[derive(Debug)]
pub struct MysqlState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<MysqlTransaction>,
    greeting_seen: bool,
}

impl State<MysqlTransaction> for MysqlState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&MysqlTransaction> {
        self.transactions.get(index)
    }
}

impl MysqlState {
    fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            greeting_seen: false,
        }
    }

    fn new_tx(&mut self) -> &mut MysqlTransaction {
        self.tx_id += 1;
        let tx = MysqlTransaction::new(self.tx_id);
        self.transactions.push_back(tx);
        self.transactions.back_mut().unwrap()
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(idx) = self.transactions.iter().position(|tx| tx.tx_id == tx_id) {
            self.transactions.remove(idx);
        }
    }

    fn get_tx(&mut self, tx_id: u64) -> Option<&MysqlTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    /// 解析 server→client 方向的数据（握手包）
    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // 只关心第一个握手包
        if self.greeting_seen {
            return AppLayerResult::ok();
        }

        match parse_mysql_greeting(input) {
            Ok((_rem, greeting)) => {
                let tx = self.new_tx();
                tx.greeting = Some(greeting);
                tx.complete = true;
                tx.tx_data.updated_tc = true;
                self.greeting_seen = true;
                AppLayerResult::ok()
            }
            Err(Err::Incomplete(_)) => {
                AppLayerResult::incomplete(0, (input.len() + 1) as u32)
            }
            Err(_) => {
                let tx = self.new_tx();
                tx.complete = true;
                tx.tx_data.set_event(MysqlEvent::MalformedGreeting as u8);
                self.greeting_seen = true;
                AppLayerResult::err()
            }
        }
    }

    /// client→server 方向 — 本次不解析
    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        let _ = input;
        AppLayerResult::ok()
    }
}

// ---- C FFI 函数 ----

extern "C" fn mysql_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    Box::into_raw(Box::new(MysqlState::new())) as *mut _
}

extern "C" fn mysql_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut MysqlState) });
}

unsafe extern "C" fn mysql_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, MysqlState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn mysql_parse_request(
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MysqlState);
    state.parse_request(stream_slice.as_slice())
}

unsafe extern "C" fn mysql_parse_response(
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MysqlState);
    state.parse_response(stream_slice.as_slice())
}

unsafe extern "C" fn mysql_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, MysqlState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn mysql_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, MysqlState);
    state.tx_id
}

unsafe extern "C" fn mysql_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, MysqlTransaction);
    if tx.complete {
        return 1;
    }
    0
}

/// 协议探测：检查是否像 MySQL 握手包
unsafe extern "C" fn mysql_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() || input_len < 5 {
        return ALPROTO_UNKNOWN;
    }
    let buf = build_slice!(input, input_len as usize);
    match parse_mysql_header(buf) {
        Ok((rem, header)) => {
            // 握手包 sequence_id 固定为 0
            if header.sequence_id != 0 {
                return ALPROTO_FAILED;
            }
            // 检查 protocol_version 字段（payload 第一个字节应为 0x0a = 10）
            if rem.is_empty() {
                return ALPROTO_UNKNOWN;
            }
            if rem[0] != 0x0a {
                return ALPROTO_FAILED;
            }
            unsafe { ALPROTO_MYSQL }
        }
        Err(Err::Incomplete(_)) => ALPROTO_UNKNOWN,
        Err(_) => ALPROTO_FAILED,
    }
}

const PARSER_NAME: &[u8] = b"mysql\0";

export_tx_data_get!(mysql_get_tx_data, MysqlTransaction);
export_state_data_get!(mysql_get_state_data, MysqlState);

#[no_mangle]
pub unsafe extern "C" fn SCMysqlRegisterParser() {
    let default_port = CString::new("[3306]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(mysql_probing_parser),
        probe_tc: Some(mysql_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: mysql_state_new,
        state_free: mysql_state_free,
        tx_free: mysql_state_tx_free,
        parse_ts: mysql_parse_request,
        parse_tc: mysql_parse_response,
        get_tx_count: mysql_state_get_tx_count,
        get_tx: mysql_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: mysql_tx_get_alstate_progress,
        get_eventinfo: Some(MysqlEvent::get_event_info),
        get_eventinfo_byid: Some(MysqlEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<MysqlState, MysqlTransaction>),
        get_tx_data: mysql_get_tx_data,
        get_state_data: mysql_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MYSQL = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个完整的 MySQL 握手包字节流
    fn build_greeting_packet(version: &str) -> Vec<u8> {
        // payload = 1 byte protocol_version + version string + NUL + 4 bytes thread_id
        let payload_len = 1 + version.len() + 1 + 4;
        let mut pkt = Vec::new();
        // header: 3 bytes LE length + 1 byte seq
        pkt.push((payload_len & 0xff) as u8);
        pkt.push(((payload_len >> 8) & 0xff) as u8);
        pkt.push(((payload_len >> 16) & 0xff) as u8);
        pkt.push(0x00); // sequence_id = 0
        // payload
        pkt.push(0x0a); // protocol_version = 10
        pkt.extend_from_slice(version.as_bytes());
        pkt.push(0x00); // NUL terminator
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // thread_id (dummy)
        pkt
    }

    #[test]
    fn test_mysql_state_parse_greeting() {
        let pkt = build_greeting_packet("8.0.32");
        let mut state = MysqlState::new();
        let result = state.parse_response(&pkt);
        assert_eq!(result.status, 0); // ok

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert!(tx.complete);
        let greeting = tx.greeting.as_ref().unwrap();
        assert_eq!(greeting.protocol_version, 10);
        assert_eq!(greeting.server_version, "8.0.32");
    }

    #[test]
    fn test_mysql_state_parse_greeting_with_distro_suffix() {
        let pkt = build_greeting_packet("5.7.38-0ubuntu0.22.04.1");
        let mut state = MysqlState::new();
        let result = state.parse_response(&pkt);
        assert_eq!(result.status, 0);

        let greeting = state.transactions[0].greeting.as_ref().unwrap();
        assert_eq!(greeting.server_version, "5.7.38-0ubuntu0.22.04.1");
    }

    #[test]
    fn test_mysql_state_only_parses_first_greeting() {
        let pkt = build_greeting_packet("8.0.32");
        let mut state = MysqlState::new();
        state.parse_response(&pkt);
        // 再次发送不应创建新事务
        state.parse_response(&pkt);
        assert_eq!(state.transactions.len(), 1);
    }

    #[test]
    fn test_mysql_state_malformed_packet() {
        let bad_data: &[u8] = &[0xff, 0xff, 0xff, 0x00, 0x03]; // protocol_version=3, 非法
        let mut state = MysqlState::new();
        let result = state.parse_response(bad_data);
        // 畸形包应该返回 err 或在 tx 上设置事件
        assert!(state.greeting_seen);
    }

    #[test]
    fn test_mysql_probing_parser_valid() {
        let pkt = build_greeting_packet("8.0.32");
        // 模拟调用 probing parser
        let result = unsafe {
            mysql_probing_parser(
                std::ptr::null(),
                0,
                pkt.as_ptr(),
                pkt.len() as u32,
                std::ptr::null_mut(),
            )
        };
        // ALPROTO_MYSQL 未注册时为 ALPROTO_UNKNOWN，但不应返回 FAILED
        assert_ne!(result, ALPROTO_FAILED);
    }

    #[test]
    fn test_mysql_probing_parser_invalid_seq() {
        // sequence_id = 5 (不是 0)
        let data: &[u8] = &[0x0e, 0x00, 0x00, 0x05, 0x0a];
        let result = unsafe {
            mysql_probing_parser(std::ptr::null(), 0, data.as_ptr(), data.len() as u32, std::ptr::null_mut())
        };
        assert_eq!(result, ALPROTO_FAILED);
    }

    #[test]
    fn test_mysql_probing_parser_invalid_protocol() {
        // protocol_version = 0x03 (不是 0x0a)
        let data: &[u8] = &[0x0e, 0x00, 0x00, 0x00, 0x03];
        let result = unsafe {
            mysql_probing_parser(std::ptr::null(), 0, data.as_ptr(), data.len() as u32, std::ptr::null_mut())
        };
        assert_eq!(result, ALPROTO_FAILED);
    }

    // ---- 基于 pcap/mysql_complete.pcap 真实抓包数据的测试 ----

    /// pcap 中 MySQL 5.0.54 握手包的完整 TCP payload
    const PCAP_GREETING: &[u8] = &[
        0x34, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x30,
        0x2e, 0x35, 0x34, 0x00, 0x5e, 0x00, 0x00, 0x00,
        0x3e, 0x7e, 0x24, 0x34, 0x75, 0x74, 0x68, 0x2c,
        0x00, 0x2c, 0xa2, 0x21, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3e, 0x36, 0x31, 0x32, 0x49,
        0x57, 0x5a, 0x3e, 0x66, 0x68, 0x57, 0x58, 0x00,
    ];

    #[test]
    fn test_pcap_state_parse_greeting() {
        let mut state = MysqlState::new();
        let result = state.parse_response(PCAP_GREETING);
        assert_eq!(result.status, 0);

        assert_eq!(state.transactions.len(), 1);
        let greeting = state.transactions[0].greeting.as_ref().unwrap();
        assert_eq!(greeting.protocol_version, 10);
        assert_eq!(greeting.server_version, "5.0.54");
    }

    #[test]
    fn test_pcap_probing_parser() {
        let result = unsafe {
            mysql_probing_parser(
                std::ptr::null(), 0,
                PCAP_GREETING.as_ptr(), PCAP_GREETING.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(result, ALPROTO_FAILED);
    }
}
