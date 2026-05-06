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

//! MMS PDU parser using ASN.1 BER decoding.
//!
//! MMS (Manufacturing Message Specification) uses ASN.1 BER encoding.
//! The top-level PDU is a CHOICE type with context-specific tags:
//!
//! MMS-PDU ::= CHOICE {
//!     confirmed-RequestPDU      [0] IMPLICIT Confirmed-RequestPDU,
//!     confirmed-ResponsePDU     [1] IMPLICIT Confirmed-ResponsePDU,
//!     confirmed-ErrorPDU        [2] IMPLICIT Confirmed-ErrorPDU,
//!     unconfirmed-PDU           [3] IMPLICIT Unconfirmed-PDU,
//!     rejectPDU                 [4] IMPLICIT RejectPDU,
//!     cancel-RequestPDU         [5] IMPLICIT INTEGER,
//!     cancel-ResponsePDU        [6] IMPLICIT INTEGER,
//!     cancel-ErrorPDU           [7] IMPLICIT Cancel-ErrorPDU,
//!     initiate-RequestPDU       [8] IMPLICIT Initiate-RequestPDU,
//!     initiate-ResponsePDU      [9] IMPLICIT Initiate-ResponsePDU,
//!     initiate-ErrorPDU         [10] IMPLICIT Initiate-ErrorPDU,
//!     conclude-RequestPDU       [11] IMPLICIT ConcludeRequestPDU,
//!     conclude-ResponsePDU      [12] IMPLICIT ConcludeResponsePDU,
//!     conclude-ErrorPDU         [13] IMPLICIT Conclude-ErrorPDU,
//! }

mod confirmed;
mod context;
mod data;
mod error;
mod file_services;
mod initiate;
mod misc_pdus;
mod name_services;
mod object_name;
mod read_write;
mod tags;
mod variable_access;

use self::confirmed::{parse_confirmed_request, parse_confirmed_response};
use self::error::MmsParseError;
use self::initiate::parse_initiate_detail;
use self::misc_pdus::{parse_confirmed_error, parse_unconfirmed_pdu};
use super::ber::{parse_ber_integer, parse_ber_tlv};
use super::mms_types::*;

/// Maximum number of variable specifications to parse from a single request.
const MAX_VARIABLE_SPECS: usize = 64;

fn is_valid_top_level_shape(tag_num: u32, is_constructed: bool) -> bool {
    match tag_num {
        // Top-level PDUs backed by SEQUENCE/CHOICE payloads are constructed.
        0 | 1 | 2 | 3 | 4 | 7 | 8 | 9 | 10 | 13 => is_constructed,
        // CancelRequest/CancelResponse carry INTEGER directly.
        // Real captures may use either primitive (0x85/0x86) or constructed
        // (0xA5/0xA6) outer tags for these single-field PDUs, so accept both.
        5 | 6 => true,
        // Conclude req/resp are zero-length IMPLICIT NULL and should be primitive.
        11 | 12 => !is_constructed,
        _ => false,
    }
}

/// 从 BER 编码数据中解析顶层 MMS PDU。
pub(super) fn parse_mms_pdu(input: &[u8]) -> Result<MmsPdu, ()> {
    parse_mms_pdu_typed(input).map_err(|_| ())
}

fn parse_mms_pdu_typed(input: &[u8]) -> Result<MmsPdu, MmsParseError> {
    // 如果输入数据为空，则返回错误
    if input.is_empty() {
        return Err(MmsParseError::malformed("empty MMS PDU"));
    }

    // 解析 BER 编码的 MMS PDU，获取tag_num
    let (tag_byte, is_constructed, tag_num, content, _remaining) =
        parse_ber_tlv(input).map_err(|_| MmsParseError::malformed("invalid top-level BER TLV"))?;
    let class = (tag_byte >> 6) & 0x03;
    if class != 0x02 || !is_valid_top_level_shape(tag_num, is_constructed) {
        return Err(MmsParseError::semantic_violation(
            "invalid top-level MMS PDU tag",
        ));
    }

    // MMS PDU is a CHOICE with context-specific tags
    match tag_num {
        0 => {
            //解析ConfirmedRequest确认请求
            parse_confirmed_request(content, 1)
        }
        1 => {
            //解析ConfirmedResponse确认响应
            parse_confirmed_response(content, 1)
        }
        2 => {
            //解析ConfirmedError确认错误
            parse_confirmed_error(content, 1)
        }
        3 => {
            //解析UnconfirmedPdu未确认 PDU
            parse_unconfirmed_pdu(content, 1)
        }
        4 => {
            //解析RejectPdu拒绝 PDU
            // RejectPDU 中 originalInvokeID 是 OPTIONAL [0] IMPLICIT Unsigned32。
            // 需区分"字段不存在"（合法 → None）和"字段存在但畸形"（→ Err）。
            let invoke_id = if content.is_empty() {
                None
            } else {
                let (tag_byte, _, _, inner, _) = parse_ber_tlv(content)
                    .map_err(|_| MmsParseError::malformed("invalid reject PDU"))?;
                if tag_byte == 0x80 {
                    // invoke_id 字段存在，必须能解析为整数
                    Some(
                        parse_ber_integer(inner)
                            .map_err(|_| MmsParseError::malformed("invalid reject invoke-id"))?,
                    )
                } else {
                    // 第一个字段不是 invoke_id（是 rejectReason），合法的 None
                    None
                }
            };
            Ok(MmsPdu::RejectPdu { invoke_id })
        }
        5 => {
            //解析CancelRequest取消请求
            // CancelRequestPDU ::= INTEGER（invoke_id 是 PDU 的全部内容）
            let invoke_id = parse_ber_integer(content)
                .map_err(|_| MmsParseError::malformed("invalid cancel request invoke-id"))?;
            Ok(MmsPdu::CancelRequest { invoke_id })
        }
        6 => {
            //解析CancelResponse取消响应
            let invoke_id = parse_ber_integer(content)
                .map_err(|_| MmsParseError::malformed("invalid cancel response invoke-id"))?;
            Ok(MmsPdu::CancelResponse { invoke_id })
        }
        7 => Ok(MmsPdu::CancelError),
        8 => {
            //解析InitiateRequest初始化请求
            let detail = parse_initiate_detail(content, 1);
            Ok(MmsPdu::InitiateRequest {
                detail: Some(detail),
            })
        }
        9 => {
            //解析InitiateResponse初始化响应
            let detail = parse_initiate_detail(content, 1);
            Ok(MmsPdu::InitiateResponse {
                detail: Some(detail),
            })
        }
        10 => Ok(MmsPdu::InitiateError),
        11 => Ok(MmsPdu::ConcludeRequest),
        12 => Ok(MmsPdu::ConcludeResponse),
        13 => Ok(MmsPdu::ConcludeError),
        _ => Err(MmsParseError::unsupported(
            "unsupported top-level MMS PDU tag",
        )),
    }
}

#[cfg(test)]
mod tests;
