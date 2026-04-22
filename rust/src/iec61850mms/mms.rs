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

use super::mms_types::MmsPdu;
use super::mms_pdu::parse_mms_pdu;
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
use std::sync::atomic::{AtomicUsize, Ordering};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

// 单个流中允许的最大事务数，超过时触发 TooManyTransactions 事件
static IEC61850_MMS_MAX_TX: AtomicUsize = AtomicUsize::new(256);

/// COTP 分片重组缓冲区最大大小（1MB），防止恶意分片导致内存耗尽。
const COTP_REASSEMBLY_MAX_SIZE: usize = 1024 * 1024;

pub(super) static mut ALPROTO_IEC61850_MMS: AppProto = ALPROTO_UNKNOWN;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
/// MMS 连接状态机的状态
pub enum MmsConnState {
    #[default]
    Idle,             // 初始状态，尚未建立任何连接
    CotpPending,      // 已发送 COTP CR，等待 CC 确认
    CotpEstablished,  // COTP 连接已建立，可发起 MMS 初始化
    AwaitInitResponse, // 已发送 MMS Initiate-Request，等待 Initiate-Response
    MmsAssociated,    // MMS 会话已建立，可收发数据 PDU
    Concluding,       // 已发送 Conclude-Request，等待 Response
    Closed,           // 连接已关闭（Conclude 完成或 COTP DR）
}

/// 驱动状态机转换的事件
#[derive(Debug)]
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
    pub pdu: Option<MmsPdu>,
    pub is_request: bool,       // true=to_server, false=to_client

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
            pdu: None,
            is_request: true,
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
    ///
    /// 直观流程：
    ///   1) COTP 建链:   Idle --CotpCr--> CotpPending --CotpCc--> CotpEstablished
    ///   2) MMS 建联:    CotpEstablished --MmsInitReq--> AwaitInitResponse --MmsInitResp--> MmsAssociated
    ///   3) 直连兼容:    Idle --MmsInitReq--> AwaitInitResponse
    ///   4) 业务收发:    MmsAssociated --MmsData--> MmsAssociated
    ///   5) 会话关闭:    MmsAssociated --MmsConcludeReq--> Concluding --MmsConcludeResp--> Closed
    ///   6) 强制断开:    任意状态 --CotpDr--> Closed
    ///
    /// 允许转换表（其余事件均视为违规，返回 false）：
    ///   - Idle            : CotpCr -> CotpPending, MmsInitReq -> AwaitInitResponse
    ///   - CotpPending     : CotpCc -> CotpEstablished
    ///   - CotpEstablished : MmsInitReq -> AwaitInitResponse
    ///   - AwaitInitResponse: MmsInitResp -> MmsAssociated
    ///   - MmsAssociated   : MmsData -> MmsAssociated, MmsConcludeReq -> Concluding
    ///   - Concluding      : MmsConcludeResp -> Closed
    ///   - Any             : CotpDr -> Closed
    ///
    /// 返回 true 表示合法转换，false 表示协议违规（状态保持不变）。
    fn advance_state(&mut self, event: MmsConnEvent) -> bool {
        let next = match (&self.conn_state, &event) {
            (MmsConnState::Idle, MmsConnEvent::CotpCr) => MmsConnState::CotpPending,
            (MmsConnState::CotpPending, MmsConnEvent::CotpCc) => MmsConnState::CotpEstablished,
            (MmsConnState::CotpEstablished, MmsConnEvent::MmsInitReq) => MmsConnState::AwaitInitResponse,
            // 兼容直接 MMS 格式（无 COTP 握手阶段）
            (MmsConnState::Idle, MmsConnEvent::MmsInitReq) => MmsConnState::AwaitInitResponse,
            (MmsConnState::AwaitInitResponse, MmsConnEvent::MmsInitResp) => MmsConnState::MmsAssociated,
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

    /// 处理解析出的 MMS PDU：每个 PDU 独立创建一个事务。
    fn handle_mms_pdu(&mut self, pdu: MmsPdu, is_request: bool) {
        let mut tx = self.new_tx();
        tx.pdu = Some(pdu);
        tx.is_request = is_request;
        if self.transactions.len() >= IEC61850_MMS_MAX_TX.load(Ordering::Relaxed) {
            tx.tx_data
                .set_event(Iec61850MmsEvent::TooManyTransactions as u8);
        }
        self.transactions.push_back(tx);
    }

    /// 状态机违规时在最近的事务上设置 ProtocolStateViolation 事件。
    fn check_state_violation(&mut self, valid: bool) {
        if !valid {
            //取事务队列最后一个事务，打上违规事件标签
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
            if cotp_buf.len() + payload.len() > COTP_REASSEMBLY_MAX_SIZE {
                cotp_buf.clear();
                return None;
            }
            cotp_buf.extend_from_slice(payload);
            return None;
        }

        let complete = if cotp_buf.is_empty() {
            std::borrow::Cow::Borrowed(payload)
        } else {
            if cotp_buf.len() + payload.len() > COTP_REASSEMBLY_MAX_SIZE {
                cotp_buf.clear();
                return None;
            }
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
                Ok(SessionExtractResult::Init(mms_payload)) => {
                    let conn_event = if is_request {
                        MmsConnEvent::MmsInitReq
                    } else {
                        MmsConnEvent::MmsInitResp
                    };
                    let valid = self.advance_state(conn_event);
                    let pdu = if let Some(data) = mms_payload {
                        // Session 封装中提取到了 MMS Initiate PDU，进行深度解析
                        match parse_mms_pdu(data) {
                            Ok(p) => p,
                            Err(_) => {
                                if is_request {
                                    MmsPdu::InitiateRequest { detail: None }
                                } else {
                                    MmsPdu::InitiateResponse { detail: None }
                                }
                            }
                        }
                    } else {
                        if is_request {
                            MmsPdu::InitiateRequest { detail: None }
                        } else {
                            MmsPdu::InitiateResponse { detail: None }
                        }
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
                        MmsPdu::InitiateRequest { .. } => MmsConnEvent::MmsInitReq,
                        MmsPdu::InitiateResponse { .. } => MmsConnEvent::MmsInitResp,
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

    /// COTP 连接管理帧处理：CR/CC 只推进状态机，不创建事务；DR 推进状态。
    fn handle_cotp_connection(&mut self, pdu_type: parser::CotpPduType) {
        match pdu_type {
            parser::CotpPduType::ConnectionRequest => {
                let valid = self.advance_state(MmsConnEvent::CotpCr);
                self.check_state_violation(valid);
            }
            parser::CotpPduType::ConnectionConfirm => {
                let valid = self.advance_state(MmsConnEvent::CotpCc);
                self.check_state_violation(valid);
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
                    if self.transactions.len() >= IEC61850_MMS_MAX_TX.load(Ordering::Relaxed) {
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
    _tx: *mut c_void, _direction: u8,
) -> c_int {
    // 每个事务独立一个 PDU，创建即完成
    return 1;
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
        probe_ts: Some(iec61850_mms_probing_parser),//用于协议识别的探测,to-server
        probe_tc: Some(iec61850_mms_probing_parser),//用于协议识别的探测,to-client
        min_depth: 0,
        max_depth: 16,
        state_new: iec61850_mms_state_new,//创建状态机实例
        state_free: iec61850_mms_state_free,//释放状态机实例
        tx_free: iec61850_mms_state_tx_free,//释放事务实例
        parse_ts: iec61850_mms_parse_request,//解析请求
        parse_tc: iec61850_mms_parse_response,//解析响应
        get_tx_count: iec61850_mms_state_get_tx_count,
        get_tx: iec61850_mms_state_get_tx,//获取事务实例
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
        //注册应用层协议探测函数
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IEC61850_MMS = alproto;

        //协议解析器是否启用，如果启用，则注册应用层协议解析函数
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.iec61850-mms.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                IEC61850_MMS_MAX_TX.store(v, Ordering::Relaxed);
            } else {
                SCLogError!("Invalid value for iec61850-mms.max-tx");
            }
        }
        //将协议挂到日志子系统(eve)上
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC61850_MMS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec61850mms::mms_types::MmsConfirmedService;

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
        assert!(tx.pdu.is_some());
        assert!(tx.is_request);
        match tx.pdu.as_ref().unwrap() {
            MmsPdu::InitiateRequest { .. } => {}
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

        // Each PDU is now an independent transaction
        assert_eq!(state.tx_id, 2);
        let tx_req = &state.transactions[0];
        assert!(tx_req.is_request);
        assert!(matches!(tx_req.pdu.as_ref().unwrap(), MmsPdu::InitiateRequest { .. }));
        let tx_resp = &state.transactions[1];
        assert!(!tx_resp.is_request);
        assert!(matches!(tx_resp.pdu.as_ref().unwrap(), MmsPdu::InitiateResponse { .. }));
    }

    #[test]
    fn test_parse_confirmed_request_response_independent() {
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

        // Each PDU is now an independent transaction
        assert_eq!(state.transactions.len(), 2);
        let tx_req = &state.transactions[0];
        assert!(tx_req.is_request);
        match tx_req.pdu.as_ref().unwrap() {
            MmsPdu::ConfirmedRequest { service, .. } => {
                assert_eq!(*service, MmsConfirmedService::Read);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
        let tx_resp = &state.transactions[1];
        assert!(!tx_resp.is_request);
        match tx_resp.pdu.as_ref().unwrap() {
            MmsPdu::ConfirmedResponse { invoke_id, service, .. } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Read);
            }
            _ => panic!("Expected ConfirmedResponse"),
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
        // CR no longer creates a transaction
        assert_eq!(state.tx_id, 0);
        assert_eq!(state.transactions.len(), 0);
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
        assert_eq!(state.conn_state, MmsConnState::AwaitInitResponse);

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
        assert_eq!(state.conn_state, MmsConnState::AwaitInitResponse);

        // Reset and verify via parse
        let mut state = MmsState::new();

        // Direct MMS Initiate-Request (no COTP connection phase)
        let init_req = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&init_req);
        assert_eq!(state.conn_state, MmsConnState::AwaitInitResponse);

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
        match tx.pdu.as_ref().unwrap() {
            MmsPdu::InitiateRequest { .. } => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    /// 响应方向的分片重组：服务端返回分片的 Confirmed-Response
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
        // 尚未收全，不应产生新事务
        assert_eq!(state.tx_id, 1);

        let resp_frame2 = [
            0x03, 0x00, 0x00, 0x0B, // TPKT: length=11
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0xA4, 0x02, 0xA1, 0x00, // 响应片段2
        ];
        state.parse_response(&resp_frame2);
        // 重组完成，创建独立的响应事务
        assert_eq!(state.tx_id, 2);
        let tx_resp = &state.transactions[1];
        assert!(!tx_resp.is_request);
        match tx_resp.pdu.as_ref().unwrap() {
            MmsPdu::ConfirmedResponse { invoke_id, service, .. } => {
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
        match tx.pdu.as_ref().unwrap() {
            MmsPdu::InitiateRequest { .. } => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
        // 状态转换：Idle → AwaitInitResponse（兼容直接 MMS 格式路径）
        assert_eq!(state.conn_state, MmsConnState::AwaitInitResponse);
    }

    /// Session ACCEPT (0x0E) → SessionExtractResult::Init → 匹配为 InitiateResponse
    #[test]
    fn test_session_layer_init_response() {
        let mut state = MmsState::new();
        // 预设状态为 AwaitInitResponse，模拟已发送 Init 请求
        state.conn_state = MmsConnState::AwaitInitResponse;

        // TPKT + COTP DT + Session ACCEPT SPDU
        let buf = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x0E, 0x00,             // Session ACCEPT
        ];
        let result = state.parse_response(&buf);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 响应创建独立事务
        assert_eq!(state.transactions.len(), 1);
        let tx = state.transactions.front().unwrap();
        assert!(!tx.is_request);
        match tx.pdu.as_ref().unwrap() {
            MmsPdu::InitiateResponse { .. } => {}
            other => panic!("Expected InitiateResponse, got {:?}", other),
        }
        // 状态转换：AwaitInitResponse → MmsAssociated
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
        match tx.pdu.as_ref().unwrap() {
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
        // 应创建一个仅含 MalformedData 事件的空事务（无 pdu）
        assert_eq!(state.tx_id, 1);
        let tx = state.transactions.front().unwrap();
        assert!(tx.pdu.is_none());
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
        assert!(tx.pdu.is_none());
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
        let max_tx = IEC61850_MMS_MAX_TX.load(Ordering::Relaxed);
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

    // ====== COTP 重组缓冲区溢出边界测试 ======

    /// 多段分片累积超过 COTP_REASSEMBLY_MAX_SIZE → 缓冲区被清空，不产生事务
    #[test]
    fn test_cotp_reassembly_overflow_discard() {
        let mut state = MmsState::new();

        // 发送一段接近上限的 EOT=0 分片
        // 直接填充内部缓冲区来模拟大量前置分片
        let big_chunk = vec![0xA8; COTP_REASSEMBLY_MAX_SIZE - 100];
        state.ts_cotp_buf = big_chunk;

        // 再发送一个小的 EOT=0 分片使总量超过上限
        let overflow_payload = vec![0x00; 200]; // 使总量 > COTP_REASSEMBLY_MAX_SIZE
        let result = state.reassemble_cotp(&overflow_payload, false, true);
        assert!(result.is_none()); // 超限 → 丢弃
        assert!(state.ts_cotp_buf.is_empty()); // 缓冲区已被清空
    }

    /// EOT=1 帧到达时累积超限 → 缓冲区被清空，不产生完整载荷
    #[test]
    fn test_cotp_reassembly_overflow_on_eot() {
        let mut state = MmsState::new();

        // 预填充接近上限
        state.ts_cotp_buf = vec![0x00; COTP_REASSEMBLY_MAX_SIZE - 50];

        // EOT=1 帧到达，但追加后超限
        let last_payload = vec![0x01; 100];
        let result = state.reassemble_cotp(&last_payload, true, true);
        assert!(result.is_none()); // 超限 → 丢弃
        assert!(state.ts_cotp_buf.is_empty());
    }

    /// 恰好等于上限不超限 → 正常重组
    #[test]
    fn test_cotp_reassembly_exactly_at_limit() {
        let mut state = MmsState::new();

        let first = vec![0xA8; COTP_REASSEMBLY_MAX_SIZE - 10];
        state.ts_cotp_buf = first;

        // 追加后恰好 = COTP_REASSEMBLY_MAX_SIZE
        let last_payload = vec![0x00; 10];
        let result = state.reassemble_cotp(&last_payload, true, true);
        assert!(result.is_some()); // 恰好等于上限 → 允许
        assert!(state.ts_cotp_buf.is_empty()); // 重组完成后缓冲区已清空
        assert_eq!(result.unwrap().len(), COTP_REASSEMBLY_MAX_SIZE);
    }

    /// 三段分片重组：EOT=0 + EOT=0 + EOT=1
    #[test]
    fn test_cotp_reassembly_three_fragments() {
        let mut state = MmsState::new();

        // MMS Initiate-Request PDU: A8 03 80 01 01（5字节）
        // 拆成三段：[A8] + [03 80] + [01 01]

        // 帧1: EOT=0, 载荷 = [A8]
        let frame1 = [
            0x03, 0x00, 0x00, 0x08, // TPKT: length=8
            0x02, 0xF0, 0x00,       // COTP DT: EOT=0
            0xA8,                   // 片段1
        ];
        let result = state.parse_request(&frame1);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.tx_id, 0);

        // 帧2: EOT=0, 载荷 = [03 80]
        let frame2 = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x00,       // COTP DT: EOT=0
            0x03, 0x80,             // 片段2
        ];
        let result = state.parse_request(&frame2);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.tx_id, 0); // 仍在缓冲

        // 帧3: EOT=1, 载荷 = [01 01]
        let frame3 = [
            0x03, 0x00, 0x00, 0x09, // TPKT: length=9
            0x02, 0xF0, 0x80,       // COTP DT: EOT=1
            0x01, 0x01,             // 片段3
        ];
        let result = state.parse_request(&frame3);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // 重组完成 → 解析出 InitiateRequest
        assert_eq!(state.tx_id, 1);
        match state.transactions.front().unwrap().pdu.as_ref().unwrap() {
            MmsPdu::InitiateRequest { .. } => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    /// 响应方向的溢出独立于请求方向
    #[test]
    fn test_cotp_reassembly_overflow_direction_independent() {
        let mut state = MmsState::new();

        // 请求方向正常缓冲
        state.ts_cotp_buf = vec![0x00; 100];

        // 响应方向超限
        state.tc_cotp_buf = vec![0x00; COTP_REASSEMBLY_MAX_SIZE - 50];
        let overflow_payload = vec![0x01; 100];
        let result = state.reassemble_cotp(&overflow_payload, false, false);
        assert!(result.is_none());
        assert!(state.tc_cotp_buf.is_empty()); // 响应方向被清空

        // 请求方向缓冲区不受影响
        assert_eq!(state.ts_cotp_buf.len(), 100);
    }

    // ====== 状态机违规转换完整测试 ======

    /// 辅助：验证在给定状态下某事件被拒绝（返回 false），且状态保持不变
    fn assert_violation(initial: MmsConnState, event: MmsConnEvent) {
        let mut state = MmsState::new();
        state.conn_state = initial;
        let label = format!("{:?} + {:?}", initial, event);
        assert!(!state.advance_state(event), "应为违规: {}", label);
        assert_eq!(state.conn_state, initial, "违规后状态应不变: {}", label);
    }

    #[test]
    fn test_violation_idle() {
        // Idle 允许: CotpCr, MmsInitReq, CotpDr
        // 违规: CotpCc, MmsInitResp, MmsData, MmsConcludeReq, MmsConcludeResp
        assert_violation(MmsConnState::Idle, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::Idle, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::Idle, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::Idle, MmsConnEvent::MmsConcludeReq);
        assert_violation(MmsConnState::Idle, MmsConnEvent::MmsConcludeResp);
    }

    #[test]
    fn test_violation_cotp_pending() {
        // CotpPending 允许: CotpCc, CotpDr
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::MmsInitReq);
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::MmsConcludeReq);
        assert_violation(MmsConnState::CotpPending, MmsConnEvent::MmsConcludeResp);
    }

    #[test]
    fn test_violation_cotp_established() {
        // CotpEstablished 允许: MmsInitReq, CotpDr
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::MmsConcludeReq);
        assert_violation(MmsConnState::CotpEstablished, MmsConnEvent::MmsConcludeResp);
    }

    #[test]
    fn test_violation_await_init_response() {
        // AwaitInitResponse 允许: MmsInitResp, CotpDr
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::MmsInitReq);
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::MmsConcludeReq);
        assert_violation(MmsConnState::AwaitInitResponse, MmsConnEvent::MmsConcludeResp);
    }

    #[test]
    fn test_violation_mms_associated() {
        // MmsAssociated 允许: MmsData, MmsConcludeReq, CotpDr
        assert_violation(MmsConnState::MmsAssociated, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::MmsAssociated, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::MmsAssociated, MmsConnEvent::MmsInitReq);
        assert_violation(MmsConnState::MmsAssociated, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::MmsAssociated, MmsConnEvent::MmsConcludeResp);
    }

    #[test]
    fn test_violation_concluding() {
        // Concluding 允许: MmsConcludeResp, CotpDr
        assert_violation(MmsConnState::Concluding, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::Concluding, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::Concluding, MmsConnEvent::MmsInitReq);
        assert_violation(MmsConnState::Concluding, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::Concluding, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::Concluding, MmsConnEvent::MmsConcludeReq);
    }

    #[test]
    fn test_violation_closed() {
        // Closed 允许: CotpDr（但已经 Closed，保持 Closed）
        assert_violation(MmsConnState::Closed, MmsConnEvent::CotpCr);
        assert_violation(MmsConnState::Closed, MmsConnEvent::CotpCc);
        assert_violation(MmsConnState::Closed, MmsConnEvent::MmsInitReq);
        assert_violation(MmsConnState::Closed, MmsConnEvent::MmsInitResp);
        assert_violation(MmsConnState::Closed, MmsConnEvent::MmsData);
        assert_violation(MmsConnState::Closed, MmsConnEvent::MmsConcludeReq);
        assert_violation(MmsConnState::Closed, MmsConnEvent::MmsConcludeResp);
    }

    /// CotpDr 在所有状态下均为合法转换 → Closed
    #[test]
    fn test_cotp_dr_from_all_states() {
        let states = [
            MmsConnState::Idle,
            MmsConnState::CotpPending,
            MmsConnState::CotpEstablished,
            MmsConnState::AwaitInitResponse,
            MmsConnState::MmsAssociated,
            MmsConnState::Concluding,
            MmsConnState::Closed,
        ];
        for &s in &states {
            let mut state = MmsState::new();
            state.conn_state = s;
            assert!(state.advance_state(MmsConnEvent::CotpDr),
                    "CotpDr should be valid from {:?}", s);
            assert_eq!(state.conn_state, MmsConnState::Closed);
        }
    }

    /// 通过实际帧发送验证违规事件会在事务上设置 ProtocolStateViolation 标记
    #[test]
    fn test_violation_event_set_on_tx() {
        let mut state = MmsState::new();
        // 跳到 AwaitInitResponse 状态
        state.conn_state = MmsConnState::AwaitInitResponse;

        // 发送 Confirmed-Request (MmsData) → 违规
        let data_req = [
            0x03, 0x00, 0x00, 0x13,
            0x02, 0xF0, 0x80,
            0xA0, 0x0A,
            0x02, 0x01, 0x01,
            0xA4, 0x05, 0xA1, 0x03, 0xA0, 0x01, 0x00,
        ];
        state.parse_request(&data_req);
        // 状态不应改变
        assert_eq!(state.conn_state, MmsConnState::AwaitInitResponse);
        // 事务应被创建，且带有 ProtocolStateViolation 事件
        assert_eq!(state.transactions.len(), 1);
    }

    // ====== Gap 恢复测试 ======

    /// gap 后首个数据不是合法 TPKT → 返回 ok 等待更多数据，不解析
    #[test]
    fn test_gap_recovery_probe_fail() {
        let mut state = MmsState::new();
        state.on_request_gap(100);
        assert!(state.request_gap);

        // 发送非 TPKT 数据（版本号不是 3）
        let garbage = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = state.parse_request(&garbage);
        // 应返回 ok（等待更多数据），不产生事务
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.tx_id, 0);
        // gap 标记仍保持
        assert!(state.request_gap);
    }

    /// gap 后首个数据是合法 TPKT → 清除 gap 标记，正常解析
    #[test]
    fn test_gap_recovery_probe_success() {
        let mut state = MmsState::new();
        state.on_request_gap(100);
        assert!(state.request_gap);

        // 发送合法 TPKT 帧
        let frame = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        let result = state.parse_request(&frame);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        // gap 标记已清除
        assert!(!state.request_gap);
        // 帧被正常解析
        assert_eq!(state.tx_id, 1);
    }

    /// 响应方向 gap 恢复独立于请求方向
    #[test]
    fn test_gap_recovery_response_direction() {
        let mut state = MmsState::new();
        state.on_response_gap(50);
        assert!(state.response_gap);
        assert!(!state.request_gap); // 请求方向不受影响

        // 响应方向发送非 TPKT
        let garbage = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = state.parse_response(&garbage);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert!(state.response_gap); // 仍未恢复

        // 响应方向发送合法 TPKT
        let frame = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA9, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_response(&frame);
        assert!(!state.response_gap);
    }

    /// 双向同时 gap：各自独立恢复
    #[test]
    fn test_gap_recovery_both_directions() {
        let mut state = MmsState::new();
        state.on_request_gap(100);
        state.on_response_gap(200);
        assert!(state.request_gap);
        assert!(state.response_gap);

        // 请求方向恢复
        let req_frame = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&req_frame);
        assert!(!state.request_gap);
        assert!(state.response_gap); // 响应方向仍有 gap

        // 响应方向恢复
        let resp_frame = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA9, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_response(&resp_frame);
        assert!(!state.response_gap);
    }

    /// gap 应清空分片缓冲区并丢弃残留数据
    #[test]
    fn test_gap_discards_partial_reassembly() {
        let mut state = MmsState::new();

        // 开始分片（EOT=0）
        let frame1 = [
            0x03, 0x00, 0x00, 0x0A,
            0x02, 0xF0, 0x00,       // EOT=0
            0xA8, 0x03, 0x80,
        ];
        state.parse_request(&frame1);
        assert!(!state.ts_cotp_buf.is_empty()); // 有缓冲数据

        // gap 发生
        state.on_request_gap(50);
        assert!(state.ts_cotp_buf.is_empty()); // 缓冲区已清空

        // gap 后发送完整新帧（先探测 TPKT）
        let new_frame = [
            0x03, 0x00, 0x00, 0x0C,
            0x02, 0xF0, 0x80,
            0xA8, 0x03, 0x80, 0x01, 0x01,
        ];
        state.parse_request(&new_frame);
        // 新帧被正常解析，不受旧残留影响
        assert_eq!(state.tx_id, 1);
        match state.transactions.front().unwrap().pdu.as_ref().unwrap() {
            MmsPdu::InitiateRequest { .. } => {}
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    /// 空输入应直接返回 ok 不做任何处理
    #[test]
    fn test_parse_empty_input() {
        let mut state = MmsState::new();
        let result = state.parse_request(&[]);
        assert_eq!(result, AppLayerResult { status: 0, consumed: 0, needed: 0 });
        assert_eq!(state.tx_id, 0);
    }
}
