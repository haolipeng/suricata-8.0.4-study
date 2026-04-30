use crate::applayer::*;
use crate::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::flow::Flow;
use nom7::Err;
use std::collections::VecDeque;
use std::ffi::CString;
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

use super::parser::{extract_hello_version, extract_info_version, parse_resp_value, RespValue};

pub(crate) static mut ALPROTO_REDIS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent, Debug, PartialEq, Eq)]
enum RedisEvent {
    MalformedResponse,
}

#[derive(Debug, PartialEq)]
enum RedisCommand {
    None,
    Hello,
    Info,
    Other,
}

#[derive(Debug)]
pub struct RedisTransaction {
    pub tx_id: u64,
    pub software_name: Option<String>,
    pub software_version: Option<String>,
    pub complete: bool,
    tx_data: AppLayerTxData,
}

impl Transaction for RedisTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl RedisTransaction {
    fn new(tx_id: u64) -> Self {
        Self {
            tx_id,
            software_name: None,
            software_version: None,
            complete: false,
            tx_data: AppLayerTxData::new(),
        }
    }
}

#[derive(Debug)]
pub struct RedisState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<RedisTransaction>,
    version_seen: bool,
    pending_command: RedisCommand,
}

impl State<RedisTransaction> for RedisState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&RedisTransaction> {
        self.transactions.get(index)
    }
}

impl RedisState {
    fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            version_seen: false,
            pending_command: RedisCommand::None,
        }
    }

    fn new_tx(&mut self) -> &mut RedisTransaction {
        self.tx_id += 1;
        let tx = RedisTransaction::new(self.tx_id);
        self.transactions.push_back(tx);
        self.transactions.back_mut().unwrap()
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(idx) = self.transactions.iter().position(|tx| tx.tx_id == tx_id) {
            self.transactions.remove(idx);
        }
    }

    fn get_tx(&mut self, tx_id: u64) -> Option<&RedisTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    /// Parse client→server (request) direction
    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // Try to identify the command
        match parse_resp_value(input) {
            Ok((_, RespValue::Array(items))) => {
                if let Some(RespValue::BulkString(cmd)) = items.first() {
                    let cmd_upper: Vec<u8> = cmd.iter().map(|b| b.to_ascii_uppercase()).collect();
                    self.pending_command = match cmd_upper.as_slice() {
                        b"HELLO" => RedisCommand::Hello,
                        b"INFO" => RedisCommand::Info,
                        _ => RedisCommand::Other,
                    };
                } else {
                    self.pending_command = RedisCommand::Other;
                }
            }
            _ => {
                self.pending_command = RedisCommand::Other;
            }
        }
        AppLayerResult::ok()
    }

    /// Parse server→client (response) direction
    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.version_seen {
            return AppLayerResult::ok();
        }

        match self.pending_command {
            RedisCommand::Hello => {
                match parse_resp_value(input) {
                    Ok((_, RespValue::Array(items))) => {
                        if let Some((name, ver)) = extract_hello_version(&items) {
                            let tx = self.new_tx();
                            tx.software_name = Some(name);
                            tx.software_version = Some(ver);
                            tx.complete = true;
                            tx.tx_data.updated_tc = true;
                            self.version_seen = true;
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        return AppLayerResult::incomplete(0, (input.len() + 1) as u32);
                    }
                    _ => {}
                }
            }
            RedisCommand::Info => {
                match parse_resp_value(input) {
                    Ok((_, RespValue::BulkString(data))) => {
                        if let Some(ver) = extract_info_version(&data) {
                            let tx = self.new_tx();
                            tx.software_name = Some("redis".to_string());
                            tx.software_version = Some(ver);
                            tx.complete = true;
                            tx.tx_data.updated_tc = true;
                            self.version_seen = true;
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        return AppLayerResult::incomplete(0, (input.len() + 1) as u32);
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        self.pending_command = RedisCommand::None;
        AppLayerResult::ok()
    }
}

// ---- C FFI functions ----

extern "C" fn redis_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    Box::into_raw(Box::new(RedisState::new())) as *mut _
}

extern "C" fn redis_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut RedisState) });
}

unsafe extern "C" fn redis_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, RedisState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn redis_parse_request(
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RedisState);
    state.parse_request(stream_slice.as_slice())
}

unsafe extern "C" fn redis_parse_response(
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RedisState);
    state.parse_response(stream_slice.as_slice())
}

unsafe extern "C" fn redis_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RedisState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn redis_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, RedisState);
    state.tx_id
}

unsafe extern "C" fn redis_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, RedisTransaction);
    if tx.complete {
        return 1;
    }
    0
}

/// Protocol probing: check if data looks like RESP
unsafe extern "C" fn redis_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() || input_len < 4 {
        return ALPROTO_UNKNOWN;
    }
    let buf = build_slice!(input, input_len as usize);
    // Check first byte is a valid RESP type marker
    match buf[0] {
        b'*' => {
            // Validate: should be *<digit(s)>\r\n
            if buf.len() < 4 {
                return ALPROTO_UNKNOWN;
            }
            // Check that bytes after * are ASCII digits (or '-' for null)
            let mut i = 1;
            if i < buf.len() && buf[i] == b'-' {
                i += 1;
            }
            while i < buf.len() && buf[i] != b'\r' {
                if !buf[i].is_ascii_digit() {
                    return ALPROTO_FAILED;
                }
                i += 1;
            }
            if i + 1 < buf.len() && buf[i] == b'\r' && buf[i + 1] == b'\n' {
                return unsafe { ALPROTO_REDIS };
            }
            ALPROTO_UNKNOWN
        }
        b'+' | b'-' | b':' | b'$' => unsafe { ALPROTO_REDIS },
        _ => ALPROTO_FAILED,
    }
}

const PARSER_NAME: &[u8] = b"redis\0";

export_tx_data_get!(redis_get_tx_data, RedisTransaction);
export_state_data_get!(redis_get_state_data, RedisState);

#[no_mangle]
pub unsafe extern "C" fn SCRedisRegisterParser() {
    let default_port = CString::new("[6379]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(redis_probing_parser),
        probe_tc: Some(redis_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: redis_state_new,
        state_free: redis_state_free,
        tx_free: redis_state_tx_free,
        parse_ts: redis_parse_request,
        parse_tc: redis_parse_response,
        get_tx_count: redis_state_get_tx_count,
        get_tx: redis_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: redis_tx_get_alstate_progress,
        get_eventinfo: Some(RedisEvent::get_event_info),
        get_eventinfo_byid: Some(RedisEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<RedisState, RedisTransaction>,
        ),
        get_tx_data: redis_get_tx_data,
        get_state_data: redis_get_state_data,
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
        ALPROTO_REDIS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_resp_array(items: &[&[u8]]) -> Vec<u8> {
        let mut buf = format!("*{}\r\n", items.len()).into_bytes();
        for item in items {
            buf.extend_from_slice(format!("${}\r\n", item.len()).as_bytes());
            buf.extend_from_slice(item);
            buf.extend_from_slice(b"\r\n");
        }
        buf
    }

    #[test]
    fn test_parse_hello_request() {
        let req = build_resp_array(&[b"HELLO", b"3"]);
        let mut state = RedisState::new();
        state.parse_request(&req);
        assert_eq!(state.pending_command, RedisCommand::Hello);
    }

    #[test]
    fn test_parse_info_request() {
        let req = build_resp_array(&[b"info"]);
        let mut state = RedisState::new();
        state.parse_request(&req);
        assert_eq!(state.pending_command, RedisCommand::Info);
    }

    #[test]
    fn test_hello_response_extracts_version() {
        let mut state = RedisState::new();
        // Send HELLO request
        let req = build_resp_array(&[b"HELLO", b"3"]);
        state.parse_request(&req);

        // Build HELLO response: flat array with key/value pairs
        let resp = build_resp_array(&[
            b"server", b"redis", b"version", b"7.2.4", b"proto", b"3",
        ]);
        // Fix: proto value should be integer, but for simplicity keep as bulk string
        let result = state.parse_response(&resp);
        assert_eq!(result.status, 0);

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert_eq!(tx.tx_id, 1);
        assert!(tx.complete);
        assert_eq!(tx.software_name.as_deref(), Some("redis"));
        assert_eq!(tx.software_version.as_deref(), Some("7.2.4"));
        assert!(state.version_seen);
    }

    #[test]
    fn test_info_response_extracts_version() {
        let mut state = RedisState::new();
        let req = build_resp_array(&[b"INFO"]);
        state.parse_request(&req);

        let info_body = b"# Server\r\nredis_version:6.2.14\r\nredis_git_sha1:00000000\r\n";
        let resp = format!("${}\r\n", info_body.len()).into_bytes();
        let mut full_resp = resp;
        full_resp.extend_from_slice(info_body);
        full_resp.extend_from_slice(b"\r\n");

        let result = state.parse_response(&full_resp);
        assert_eq!(result.status, 0);

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert_eq!(tx.software_name.as_deref(), Some("redis"));
        assert_eq!(tx.software_version.as_deref(), Some("6.2.14"));
    }

    #[test]
    fn test_version_only_extracted_once() {
        let mut state = RedisState::new();

        // First HELLO
        let req = build_resp_array(&[b"HELLO", b"3"]);
        state.parse_request(&req);
        let resp = build_resp_array(&[b"server", b"redis", b"version", b"7.2.4"]);
        state.parse_response(&resp);

        // Second HELLO should be ignored
        state.parse_request(&req);
        state.parse_response(&resp);

        assert_eq!(state.transactions.len(), 1);
    }

    #[test]
    fn test_probing_parser_valid_array() {
        let data = b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n";
        let result = unsafe {
            redis_probing_parser(
                std::ptr::null(),
                0,
                data.as_ptr(),
                data.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(result, ALPROTO_FAILED);
    }

    #[test]
    fn test_probing_parser_invalid() {
        let data = b"GET / HTTP/1.1\r\n";
        let result = unsafe {
            redis_probing_parser(
                std::ptr::null(),
                0,
                data.as_ptr(),
                data.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, ALPROTO_FAILED);
    }
}
