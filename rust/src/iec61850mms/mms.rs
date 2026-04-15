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

use super::mms_pdu::{MmsPdu, parse_mms_pdu};
use super::session::{SessionExtractResult, is_direct_mms_pdu, extract_mms_from_session};
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

// 单个流中允许的最大事务数，超过时触发 TooManyTransactions 事件
static mut IEC61850_MMS_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_IEC61850_MMS: AppProto = ALPROTO_UNKNOWN;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
/// MMS 连接状态机的状态
pub enum MmsConnState {
    #[default]
    Idle,             // 初始状态，尚未建立任何连接
    CotpPending,      // 已发送 COTP CR，等待 CC 确认
    CotpEstablished,  // COTP 连接已建立，可发起 MMS 初始化
    InitPending,      // 已发送 MMS Initiate-Request，等待 Response
    MmsAssociated,    // MMS 会话已建立，可收发数据 PDU
    Concluding,       // 已发送 Conclude-Request，等待 Response
    Closed,           // 连接已关闭（Conclude 完成或 COTP DR）
}

/// 驱动状态机转换的事件
enum MmsConnEvent {
    CotpCr,          // 收到 COTP Connection Request
    CotpCc,          // 收到 COTP Connection Confirm
    CotpDr,          // 收到 COTP Disconnect Request（任何状态均可转 Closed）
    MmsInitReq,      // 收到 MMS Initiate-Request
    MmsInitResp,     // 收到 MMS Initiate-Response
    MmsData,         // 收到普通数据 PDU（Confirmed/Unconfirmed 等）
    MmsConcludeReq,  // 收到 MMS Conclude-Request
    MmsConcludeResp, // 收到 MMS Conclude-Response
}

#[derive(AppLayerEvent)]
/// 应用层事件，用于 Suricata 规则中的 app-layer-event 匹配
enum Iec61850MmsEvent {
    TooManyTransactions,    // 事务数超过 IEC61850_MMS_MAX_TX 上限
    MalformedData,          // BER 解码或帧解析失败
    ProtocolStateViolation, // 状态机检测到非法的协议状态转换
}

pub struct MmsTransaction {
    tx_id: u64,
    pub request: Option<MmsPdu>,
    pub response: Option<MmsPdu>,
    pub invoke_id: Option<u32>, // Confirmed 类 PDU 的 invokeID，用于请求/响应匹配

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
    request_gap: bool,  // 请求方向发生过 TCP gap，需等待下一个 TPKT 头重新同步
    response_gap: bool, // 响应方向发生过 TCP gap
    conn_state: MmsConnState, // 当前连接状态机的状态
    ts_cotp_buf: Vec<u8>, // 请求方向的 COTP 分片重组缓冲区
    tc_cotp_buf: Vec<u8>, // 响应方向的 COTP 分片重组缓冲区
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

    /// 状态机转换：根据当前状态和事件决定下一状态。
    /// 返回 true 表示合法转换，false 表示协议违规（状态不变）。
    fn advance_state(&mut self, event: MmsConnEvent) -> bool {
        let next = match (&self.conn_state, &event) {
            (MmsConnState::Idle, MmsConnEvent::CotpCr) => MmsConnState::CotpPending,
            (MmsConnState::CotpPending, MmsConnEvent::CotpCc) => MmsConnState::CotpEstablished,
            (MmsConnState::CotpEstablished, MmsConnEvent::MmsInitReq) => MmsConnState::InitPending,
            // 兼容直接 MMS 格式（无 COTP 握手阶段）
            (MmsConnState::Idle, MmsConnEvent::MmsInitReq) => MmsConnState::InitPending,
            (MmsConnState::InitPending, MmsConnEvent::MmsInitResp) => MmsConnState::MmsAssociated,
            // MmsAssociated 状态下可反复收发数据 PDU
            (MmsConnState::MmsAssociated, MmsConnEvent::MmsData) => MmsConnState::MmsAssociated,
            (MmsConnState::MmsAssociated, MmsConnEvent::MmsConcludeReq) => MmsConnState::Concluding,
            (MmsConnState::Concluding, MmsConnEvent::MmsConcludeResp) => MmsConnState::Closed,
            // COTP 断连在任何状态下都直接转为 Closed
            (_, MmsConnEvent::CotpDr) => MmsConnState::Closed,
            _ => {
                return false;
            }
        };
        self.conn_state = next;
        true
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

    /// 处理解析出的 MMS PDU：请求创建新事务，响应匹配已有事务。
    /// 响应匹配策略：先按 invoke_id 精确匹配，回退到第一个未响应的事务。
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

            // 按 invoke_id 查找匹配的请求事务
            let match_idx = if let Some(id) = invoke_id {
                self.transactions
                    .iter()
                    .position(|tx| tx.invoke_id == Some(id) && tx.response.is_none())
            } else {
                None
            };

            // 回退：取第一个尚无响应的事务
            let target_idx = match_idx.or_else(|| {
                self.transactions
                    .iter()
                    .position(|tx| tx.response.is_none())
            });

            if let Some(idx) = target_idx {
                self.transactions[idx].tx_data.updated_tc = true;
                self.transactions[idx].response = Some(pdu);
            } else {
                // 无匹配请求，创建仅含响应的独立事务
                let mut tx = self.new_tx();
                tx.invoke_id = invoke_id;
                tx.tx_data.updated_tc = true;
                tx.response = Some(pdu);
                self.transactions.push_back(tx);
            }
        }
    }

    /// 状态机违规时在最近的事务上设置 ProtocolStateViolation 事件。
    /// 用于 Session Init、MMS PDU 解析、COTP CR 三条路径。
    /// 注意：COTP CC 路径的事件设置在 find_open_request() 上，不使用此方法。
    fn check_state_violation(&mut self, valid: bool) {
        if !valid {
            if let Some(tx) = self.transactions.back_mut() {
                tx.tx_data
                    .set_event(Iec61850MmsEvent::ProtocolStateViolation as u8);
            }
        }
    }

    /// 创建仅含 MalformedData 事件的空事务。
    fn emit_malformed_tx(&mut self) {
        let mut tx = self.new_tx();
        tx.tx_data
            .set_event(Iec61850MmsEvent::MalformedData as u8);
        self.transactions.push_back(tx);
    }

    /// COTP 分片重组：EOT=0 缓冲数据返回 None；EOT=1 返回完整载荷。
    /// 保留 Cow::Borrowed 零拷贝优化（非分片帧不拷贝）。
    fn reassemble_cotp<'a>(
        &mut self, payload: &'a [u8], last_unit: bool, is_request: bool,
    ) -> Option<std::borrow::Cow<'a, [u8]>> {
        let cotp_buf = if is_request {
            &mut self.ts_cotp_buf
        } else {
            &mut self.tc_cotp_buf
        };

        if !last_unit {
            cotp_buf.extend_from_slice(payload);
            return None;
        }

        let complete = if cotp_buf.is_empty() {
            std::borrow::Cow::Borrowed(payload)
        } else {
            cotp_buf.extend_from_slice(payload);
            let assembled = std::borrow::Cow::Owned(cotp_buf.clone());
            cotp_buf.clear();
            assembled
        };
        Some(complete)
    }

    /// 完整 COTP 载荷的分发处理：判断直接 MMS / Session 封装，
    /// 解析 MMS PDU，驱动状态机，检测协议违规。
    fn handle_cotp_payload(&mut self, payload: &[u8], is_request: bool) {
        let mms_data = if is_direct_mms_pdu(payload) {
            Some(payload)
        } else {
            match extract_mms_from_session(payload) {
                Ok(SessionExtractResult::Mms(data)) => Some(data),
                Ok(SessionExtractResult::Init) => {
                    let conn_event = if is_request {
                        MmsConnEvent::MmsInitReq
                    } else {
                        MmsConnEvent::MmsInitResp
                    };
                    let valid = self.advance_state(conn_event);
                    let pdu = if is_request {
                        MmsPdu::InitiateRequest
                    } else {
                        MmsPdu::InitiateResponse
                    };
                    self.handle_mms_pdu(pdu, is_request);
                    self.check_state_violation(valid);
                    None
                }
                Ok(SessionExtractResult::SessionClose) => {
                    self.advance_state(MmsConnEvent::CotpDr);
                    None
                }
                Err(_) => {
                    self.emit_malformed_tx();
                    None
                }
            }
        };

        if let Some(data) = mms_data {
            match parse_mms_pdu(data) {
                Ok(pdu) => {
                    let conn_event = match &pdu {
                        MmsPdu::InitiateRequest => MmsConnEvent::MmsInitReq,
                        MmsPdu::InitiateResponse => MmsConnEvent::MmsInitResp,
                        MmsPdu::ConcludeRequest => MmsConnEvent::MmsConcludeReq,
                        MmsPdu::ConcludeResponse => MmsConnEvent::MmsConcludeResp,
                        _ => MmsConnEvent::MmsData,
                    };
                    let valid = self.advance_state(conn_event);
                    self.handle_mms_pdu(pdu, is_request);
                    self.check_state_violation(valid);
                }
                Err(_) => {
                    self.emit_malformed_tx();
                }
            }
        }
    }

    /// COTP 连接管理帧处理：CR 创建事务，CC 更新已有事务，DR 推进状态。
    fn handle_cotp_connection(&mut self, pdu_type: parser::CotpPduType) {
        match pdu_type {
            parser::CotpPduType::ConnectionRequest => {
                let valid = self.advance_state(MmsConnEvent::CotpCr);
                let tx = self.new_tx();
                self.transactions.push_back(tx);
                self.check_state_violation(valid);
            }
            parser::CotpPduType::ConnectionConfirm => {
                let valid = self.advance_state(MmsConnEvent::CotpCc);
                if let Some(tx) = self.find_open_request() {
                    tx.tx_data.updated_tc = true;
                    if !valid {
                        tx.tx_data.set_event(
                            Iec61850MmsEvent::ProtocolStateViolation as u8,
                        );
                    }
                }
            }
            parser::CotpPduType::DisconnectRequest => {
                self.advance_state(MmsConnEvent::CotpDr);
            }
            _ => {}
        }
    }

    /// 解析 TPKT/COTP 帧流。处理三个阶段：
    /// 1. 循环提取 TPKT 帧并按 COTP 类型分发
    /// 2. 对 DataTransfer 帧：重组分片后交由 handle_cotp_payload 处理
    /// 3. 对连接管理帧：交由 handle_cotp_connection 处理
    fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // gap 恢复：该方向发生过 TCP segment 缺失后，不再信任当前字节流偏移。
        // 先探测输入是否从合法 TPKT 头开始；若不是，先返回 ok 等待更多数据，
        // 避免在错误偏移上继续 BER/TPKT 解析引发连锁 malformed。
        if is_request && self.request_gap {
            if !parser::probe_tpkt(input) {
                return AppLayerResult::ok();
            }
            // 命中合法 TPKT 头，说明请求方向已重新对齐协议边界，清除 gap 标记。
            self.request_gap = false;
        } else if !is_request && self.response_gap {
            if !parser::probe_tpkt(input) {
                return AppLayerResult::ok();
            }
            // 命中合法 TPKT 头，说明响应方向已重新对齐协议边界，清除 gap 标记。
            self.response_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_tpkt_cotp_frame(start) {
                Ok((rem, frame)) => {
                    if frame.cotp.pdu_type == parser::CotpPduType::DataTransfer
                        && !frame.payload.is_empty()
                    {
                        if let Some(complete) = self.reassemble_cotp(
                            frame.payload, frame.cotp.last_unit, is_request,
                        ) {
                            self.handle_cotp_payload(&complete, is_request);
                        }
                    } else {
                        self.handle_cotp_connection(frame.cotp.pdu_type);
                    }
                    start = rem;
                    if self.transactions.len() >= unsafe { IEC61850_MMS_MAX_TX } {
                        return AppLayerResult::err();
                    }
                }
                //当前输入字节还不够，让上层继续缓存并等待更多 TCP 数据再解析
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                //协议解析错误
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    /// 解析请求方向的 TPKT/COTP 帧流。
    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        self.parse_frames(input, true)
    }

    /// 解析响应方向的 TPKT/COTP 帧流。
    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        self.parse_frames(input, false)
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
        self.ts_cotp_buf.clear(); // gap 后残留的分片数据不可靠，必须丢弃
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
        self.tc_cotp_buf.clear();
    }
}

// C exports.

unsafe extern "C" fn iec61850_mms_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 4 && !input.is_null() {
        // 至少需要 4 字节：TPKT 头（3 字节） + COTP 头（1 字节）
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

    #[test]
    fn test_conn_state_normal_flow() {
        let mut state = MmsState::new();
        assert_eq!(state.conn_state, MmsConnState::Idle);

        // COTP CR
        let cr_buf = [
            0x03, 0x00, 0x00, 0x0B,
            0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0xC0,
        ];
        state.parse_request(&cr_buf);
        assert_eq!(state.conn_state, MmsConnState::CotpPending);

        // COTP CC
        let cc_buf = [
            0x03, 0x00, 0x00, 0x0B,
            0x06, 0xD0, 0x00, 0x00, 0x00, 0x01, 0xC0,
        ];
        state.parse_response(&cc_buf);
        assert_eq!(state.conn_state, MmsConnState::CotpEstablished);

        // MMS Initiate-Request
        let init_req = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&init_req);
        assert_eq!(state.conn_state, MmsConnState::InitPending);

        // MMS Initiate-Response
        let init_resp = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA9, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_response(&init_resp);
        assert_eq!(state.conn_state, MmsConnState::MmsAssociated);

        // MMS Confirmed-Request (data)
        let data_req = [
            0x03, 0x00, 0x00, 0x13,
            0x02, 0xF0, 0x80,
            0xA0, 0x0A,
            0x02, 0x01, 0x01,
            0xA4, 0x05, 0xA1, 0x03, 0xA0, 0x01, 0x00,
        ];
        state.parse_request(&data_req);
        assert_eq!(state.conn_state, MmsConnState::MmsAssociated);

        // MMS Conclude-Request
        let conclude_req = [
            0x03, 0x00, 0x00, 0x09,
            0x02, 0xF0, 0x80,
            0xAB, 0x00,
        ];
        state.parse_request(&conclude_req);
        assert_eq!(state.conn_state, MmsConnState::Concluding);

        // MMS Conclude-Response
        let conclude_resp = [
            0x03, 0x00, 0x00, 0x09,
            0x02, 0xF0, 0x80,
            0xAC, 0x00,
        ];
        state.parse_response(&conclude_resp);
        assert_eq!(state.conn_state, MmsConnState::Closed);
    }

    #[test]
    fn test_conn_state_data_before_association() {
        let mut state = MmsState::new();
        assert_eq!(state.conn_state, MmsConnState::Idle);

        // MmsData in Idle state should be a violation
        assert!(!state.advance_state(MmsConnEvent::MmsData));
        // State should remain Idle (not changed on violation)
        assert_eq!(state.conn_state, MmsConnState::Idle);

        // Also verify via parse: send Confirmed-Request directly in Idle state
        let data_req = [
            0x03, 0x00, 0x00, 0x13,
            0x02, 0xF0, 0x80,
            0xA0, 0x0A,
            0x02, 0x01, 0x01,
            0xA4, 0x05, 0xA1, 0x03, 0xA0, 0x01, 0x00,
        ];
        state.parse_request(&data_req);
        // State should still be Idle (violation doesn't advance state)
        assert_eq!(state.conn_state, MmsConnState::Idle);
    }

    #[test]
    fn test_conn_state_direct_mms_format() {
        let mut state = MmsState::new();
        assert_eq!(state.conn_state, MmsConnState::Idle);

        // Idle + MmsInitReq should be a valid transition (direct MMS format)
        assert!(state.advance_state(MmsConnEvent::MmsInitReq));
        assert_eq!(state.conn_state, MmsConnState::InitPending);

        // Reset and verify via parse
        let mut state = MmsState::new();

        // Direct MMS Initiate-Request (no COTP connection phase)
        let init_req = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&init_req);
        assert_eq!(state.conn_state, MmsConnState::InitPending);

        // Initiate-Response
        let init_resp = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA9, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_response(&init_resp);
        assert_eq!(state.conn_state, MmsConnState::MmsAssociated);
    }

    // ====== COTP 分片重组测试 ======

    /// 基本场景：MMS PDU 被拆成 2 个 COTP DT 帧（EOT=0 + EOT=1）
    #[test]
    fn test_cotp_reassembly_two_fragments() {
        let mut state = MmsState::new();

        // 构造一个 MMS Initiate-Request PDU: A8 03 80 01 01 (5字节)
        // 拆成两帧发送：
        //   帧1: COTP DT, EOT=0, 载荷 = [A8 03 80]     (前3字节)
        //   帧2: COTP DT, EOT=1, 载荷 = [01 01]         (后2字节)

        // 帧1: TPKT(length=10) + COTP DT(EOT=0) + 3字节片段
        let frame1 = [
            0x03, 0x00, 0x00, 0x0A, // TPKT: version=3, length=10
            0x02, 0xF0, 0x00,       // COTP DT: length=2, type=0xF0, EOT=0 (0x00)
            0xA8, 0x03, 0x80,       // MMS 片段1 (不完整)
        ];
        let result = state.parse_request(&frame1);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // EOT=0 → 缓冲中，不应产生任何事务
        assert_eq!(state.tx_id, 0);

        // 帧2: TPKT(length=9) + COTP DT(EOT=1) + 2字节片段
        let frame2 = [
            0x03, 0x00, 0x00, 0x09, // TPKT: version=3, length=9
            0x02, 0xF0, 0x80,       // COTP DT: length=2, type=0xF0, EOT=1 (0x80)
            0x01, 0x01,             // MMS 片段2
        ];
        let result = state.parse_request(&frame2);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // EOT=1 → 重组完成，应成功解析出 InitiateRequest
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        match tx.request.as_ref().unwrap() {
            MmsPdu::InitiateRequest => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    /// 响应���向的分片重组：服务端返回分片的 Confirmed-Response
    #[test]
    fn test_cotp_reassembly_response_direction() {
        let mut state = MmsState::new();

        // 先创建一个请求事务
        let req_buf = [
            0x03, 0x00, 0x00, 0x13,
            0x02, 0xF0, 0x80,
            0xA0, 0x0A,
            0x02, 0x01, 0x01, // invokeID=1
            0xA4, 0x05, 0xA1, 0x03, 0xA0, 0x01, 0x00,
        ];
        state.parse_request(&req_buf);
        assert_eq!(state.tx_id, 1);

        // Confirmed-Response: A1 07 02 01 01 A4 02 A1 00 (9字节)
        // 拆成两帧：
        //   帧1 (EOT=0): [A1 07 02 01 01]  (5字节)
        //   帧2 (EOT=1): [A4 02 A1 00]     (4字节)

        let resp_frame1 = [
            0x03, 0x00, 0x00, 0x0C, // TPKT: length=12
            0x02, 0xF0, 0x00,       // COTP DT: EOT=0
            0xA1, 0x07, 0x02, 0x01, 0x01, // 响应片段1
        ];
        state.parse_response(&resp_frame1);
        // 尚未收全，事务不应有 response
        let tx = state.transactions.front().unwrap();
        assert!(tx.response.is_none());

        let resp_frame2 = [
            0x03, 0x00, 0x00, 0x0B, // TPKT: length=11
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0xA4, 0x02, 0xA1, 0x00, // 响应片段2
        ];
        state.parse_response(&resp_frame2);
        // 重组完成，应匹配到 invokeID=1 的事务
        let tx = state.transactions.front().unwrap();
        assert!(tx.response.is_some());
        match tx.response.as_ref().unwrap() {
            MmsPdu::ConfirmedResponse { invoke_id, service } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Read);
            }
            other => panic!("Expected ConfirmedResponse, got {:?}", other),
        }
    }

    /// 非分片帧（EOT=1）应继续正常工作，不走缓冲区
    #[test]
    fn test_cotp_reassembly_single_frame_unchanged() {
        let mut state = MmsState::new();
        // 单帧 EOT=1，和之前的测试一样
        let buf = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80, // EOT=1
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.tx_id, 1);
    }

    /// 两个方向的分片互不干扰
    #[test]
    fn test_cotp_reassembly_independent_directions() {
        let mut state = MmsState::new();

        // 请求方向帧1 (EOT=0): Initiate-Request 前半段
        let req_f1 = [
            0x03, 0x00, 0x00, 0x0A,
            0x02, 0xF0, 0x00, // EOT=0
            0xA8, 0x03, 0x80,
        ];
        state.parse_request(&req_f1);
        assert_eq!(state.tx_id, 0); // 请求方向还在缓冲

        // 响应方向帧 (EOT=1): 完整的 Initiate-Response（不受请求方向影响）
        let resp = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80, // EOT=1
            0xA9, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_response(&resp);
        // 响应方向独立完成，创建了只有 response 的事务
        assert_eq!(state.tx_id, 1);

        // 请求方向帧2 (EOT=1): 补齐
        let req_f2 = [
            0x03, 0x00, 0x00, 0x09,
            0x02, 0xF0, 0x80, // EOT=1
            0x01, 0x01,
        ];
        state.parse_request(&req_f2);
        // 请求方向重组完成
        assert_eq!(state.tx_id, 2);
    }

    /// TCP gap 应清空重组缓冲区
    #[test]
    fn test_cotp_reassembly_gap_clears_buffer() {
        let mut state = MmsState::new();

        // 帧1 (EOT=0): 开始分片
        let frame1 = [
            0x03, 0x00, 0x00, 0x0A,
            0x02, 0xF0, 0x00, // EOT=0
            0xA8, 0x03, 0x80,
        ];
        state.parse_request(&frame1);
        assert_eq!(state.tx_id, 0);

        // 发生 TCP gap → 缓冲区中的不完整数据应被丢弃
        state.on_request_gap(100);

        // gap 后收到新的完整帧，应能正常解析（不受之前残留数据影响）
        let fresh = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&fresh);
        assert_eq!(state.tx_id, 1);
    }

    #[test]
    fn test_conn_state_cotp_disconnect() {
        let mut state = MmsState::new();

        // Establish COTP connection
        let cr_buf = [
            0x03, 0x00, 0x00, 0x0B,
            0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0xC0,
        ];
        state.parse_request(&cr_buf);
        let cc_buf = [
            0x03, 0x00, 0x00, 0x0B,
            0x06, 0xD0, 0x00, 0x00, 0x00, 0x01, 0xC0,
        ];
        state.parse_response(&cc_buf);
        assert_eq!(state.conn_state, MmsConnState::CotpEstablished);

        // COTP Disconnect Request (type 0x80)
        let dr_buf = [
            0x03, 0x00, 0x00, 0x0B,
            0x06, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        state.parse_request(&dr_buf);
        assert_eq!(state.conn_state, MmsConnState::Closed);
    }

    // ====== Session/Presentation 层测试 ======

    /// Session CONNECT (0x0D) → SessionExtractResult::Init → 创建 InitiateRequest 事务
    #[test]
    fn test_session_layer_init_request() {
        let mut state = MmsState::new();
        // TPKT + COTP DT + Session CONNECT SPDU (type=0x0D, length=0x00)
        let buf = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x0D, 0x00,             // Session CONNECT
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // Init 路径应创建 InitiateRequest 事务
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        match tx.request.as_ref().unwrap() {
            MmsPdu::InitiateRequest => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
        // 状态转换：Idle → InitPending（兼容直接 MMS 格式路径）
        assert_eq!(state.conn_state, MmsConnState::InitPending);
    }

    /// Session ACCEPT (0x0E) → SessionExtractResult::Init → 匹配为 InitiateResponse
    #[test]
    fn test_session_layer_init_response() {
        let mut state = MmsState::new();
        // 预设状态为 InitPending，模拟已发送 Init 请求
        state.conn_state = MmsConnState::InitPending;
        let mut tx = state.new_tx();
        tx.request = Some(MmsPdu::InitiateRequest);
        state.transactions.push_back(tx);

        // TPKT + COTP DT + Session ACCEPT SPDU
        let buf = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x0E, 0x00,             // Session ACCEPT
        ];
        let result = state.parse_response(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 响应应匹配到已有的请求事务
        assert_eq!(state.transactions.len(), 1);
        let tx = state.transactions.front().unwrap();
        match tx.response.as_ref().unwrap() {
            MmsPdu::InitiateResponse => {}
            other => panic!("Expected InitiateResponse, got {:?}", other),
        }
        // 状态转换：InitPending → MmsAssociated
        assert_eq!(state.conn_state, MmsConnState::MmsAssociated);
    }

    /// Session FINISH (0x09) → SessionExtractResult::SessionClose → 状态转 Closed
    #[test]
    fn test_session_layer_close() {
        let mut state = MmsState::new();
        // 预设为 MmsAssociated 状态
        state.conn_state = MmsConnState::MmsAssociated;

        // TPKT + COTP DT + Session FINISH SPDU
        let buf = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x09, 0x00,             // Session FINISH
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // SessionClose 不创建事务，只推进状态机
        assert_eq!(state.tx_id, 0);
        assert_eq!(state.transactions.len(), 0);
        // 状态转换：MmsAssociated → Closed（经由 CotpDr 事件）
        assert_eq!(state.conn_state, MmsConnState::Closed);
    }

    /// Session Give Tokens + Data Transfer + Presentation 层 → 提取并解析 MMS PDU
    #[test]
    fn test_session_layer_mms_data() {
        let mut state = MmsState::new();
        // 预设为 MmsAssociated 状态
        state.conn_state = MmsConnState::MmsAssociated;

        // 完整的 Session/Presentation/MMS 协议栈：
        //   Session: Give Tokens (01 00) + Data Transfer (01 00)
        //   Presentation: fully-encoded-data [APPLICATION 1] (0x61)
        //     PDV-list: SEQUENCE (0x30)
        //       context-id: INTEGER = 3
        //       single-ASN1-type [0]: MMS ConcludeRequest (0xAB 0x00)
        let buf = [
            0x03, 0x00, 0x00, 0x16, // TPKT: length=22
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            // Session: Give Tokens + Data Transfer
            0x01, 0x00, 0x01, 0x00,
            // Presentation: fully-encoded-data
            0x61, 0x09,             // [APPLICATION 1], length=9
            0x30, 0x07,             // SEQUENCE (PDV-list entry), length=7
            0x02, 0x01, 0x03,       // INTEGER presentation-context-id=3
            0xA0, 0x02,             // [0] single-ASN1-type wrapper, length=2
            0xAB, 0x00,             // MMS ConcludeRequest
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 应成功提取并解析出 ConcludeRequest
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        match tx.request.as_ref().unwrap() {
            MmsPdu::ConcludeRequest => {}
            other => panic!("Expected ConcludeRequest, got {:?}", other),
        }
        // 状态转换：MmsAssociated → Concluding
        assert_eq!(state.conn_state, MmsConnState::Concluding);
    }

    // ====== 畸形数据测试 ======

    /// 直接 MMS 标签但 BER 编码无效 → parse_mms_pdu 失败 → MalformedData 事务
    #[test]
    fn test_malformed_mms_pdu() {
        let mut state = MmsState::new();
        // 0xA0 在 MMS 标签范围内，但声明长度=16 而实际只有 1 字节内容
        let buf = [
            0x03, 0x00, 0x00, 0x0A, // TPKT: length=10
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0xA0, 0x10, 0x01,       // Invalid MMS: tag=0xA0, length=16, only 1 byte
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 应创建一个仅含 MalformedData 事件的空事务（无 request/response）
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(tx.request.is_none());
        assert!(tx.response.is_none());
    }

    /// 非 MMS 且非合法 Session SPDU → extract_mms_from_session 返回 Err → MalformedData
    #[test]
    fn test_malformed_session_data() {
        let mut state = MmsState::new();
        // 0x55 既不在 MMS 标签范围，也不是有效 Session SPDU 类型
        let buf = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x55, 0x00,             // Unknown SPDU type
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 同样创建仅含事件的空事务
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(tx.request.is_none());
        assert!(tx.response.is_none());
    }

    // ====== Incomplete 帧测试 ======

    /// TPKT 声明长度 > 实际可用字节 → 返回 AppLayerResult::incomplete
    #[test]
    fn test_incomplete_tpkt() {
        let mut state = MmsState::new();
        // TPKT header 声明 length=12，但只提供 7 字节（载荷不完整）
        let buf = [
            0x03, 0x00, 0x00, 0x0C, // TPKT: length=12
            0x02, 0xF0, 0x80,       // COTP DT 头（3 字节，TPKT 需要 8 字节载荷）
        ];
        let result = state.parse_request(&buf);
        // incomplete: consumed=0（首帧即不完整），needed=buf.len()+1=8
        assert_eq!(result, AppLayerResult { status: 1, consumed: 0, needed: 8 });
        // 不应创建任何事务
        assert_eq!(state.tx_id, 0);
    }

    /// 第一帧完整、第二帧不完整 → 返回已消费字节数 + 所需字节数
    #[test]
    fn test_incomplete_second_frame() {
        let mut state = MmsState::new();
        let mut buf = Vec::new();
        // 帧1: 完整的 Initiate-Request（12 字节）
        buf.extend_from_slice(&[
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ]);
        // 帧2: 不完整的 TPKT 头（仅 2 字节）
        buf.extend_from_slice(&[0x03, 0x00]);

        let result = state.parse_request(&buf);
        // 帧1 消费 12 字节；帧2 剩余 2 字节不完整，需要 3 字节
        assert_eq!(result, AppLayerResult { status: 1, consumed: 12, needed: 3 });
        // 帧1 应成功解析
        assert_eq!(state.tx_id, 1);
    }

    // ====== 事务数超限测试 ======

    /// 事务数达到 MAX_TX 上限 → parse_frames 返回 AppLayerResult::err()
    #[test]
    fn test_too_many_transactions() {
        let mut state = MmsState::new();
        let max_tx = unsafe { IEC61850_MMS_MAX_TX };
        // 预填充 max_tx - 1 个事务
        for _ in 0..max_tx - 1 {
            let tx = state.new_tx();
            state.transactions.push_back(tx);
        }
        assert_eq!(state.transactions.len(), max_tx - 1);

        // 再解析一帧 → 事务数达到 max_tx → 触发超限返回 err
        let buf = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        let result = state.parse_request(&buf);
        assert_eq!(result, AppLayerResult { status: -1, consumed: 0, needed: 0 });
    }
}
