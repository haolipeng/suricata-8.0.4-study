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

//! OSI Session/Presentation 层解包。
//!
//! 负责从 Session SPDU 和 Presentation fully-encoded-data 中
//! 提取 MMS PDU 载荷，以及识别 Session 连接/断开事件。

use super::ber::{parse_ber_integer, parse_ber_tlv};

/// Session/Presentation 层解包结果。
pub(super) enum SessionExtractResult<'a> {
    /// 成功提取到 MMS PDU 载荷。
    Mms(&'a [u8]),
    /// Session CONNECT/ACCEPT，属于初始化阶段。
    Init,
    /// Session FINISH/DISCONNECT，属于会话收尾阶段。
    SessionClose,
}

/// 判断载荷是否直接以 MMS PDU 标签开头（无 Session/Presentation 封装）。
/// MMS PDU 使用 ASN.1 上下文标签 [0]~[13]，BER 编码时：
///   - constructed 形式：0xA0~0xAD（如 confirmed-RequestPDU [0] SEQUENCE）
///   - primitive 形式：0x80~0x8D（如 conclude-RequestPDU [11] NULL → 0x8B）
/// 两种编码均为合法 MMS PDU，需同时识别。
pub(super) fn is_direct_mms_pdu(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let b = payload[0];
    (0xA0..=0xAD).contains(&b) || (0x80..=0x8D).contains(&b)
}

/// 从 OSI Session/Presentation 层封装中提取 MMS PDU。
/// 返回值：
/// - `Ok(SessionExtractResult::Mms(mms_payload))`：成功剥离封装并提取到 MMS 载荷
/// - `Ok(SessionExtractResult::Init)`：当前为 Session CONNECT/ACCEPT（初始化阶段）
/// - `Ok(SessionExtractResult::SessionClose)`：当前为 Session FINISH/DISCONNECT（收尾阶段）
/// - `Err(())`：解析失败
pub(super) fn extract_mms_from_session(payload: &[u8]) -> Result<SessionExtractResult<'_>, ()> {
    if payload.len() < 2 {
        return Err(());
    }

    let spdu_type = payload[0];

    match spdu_type {
        // Session CONNECT (0x0D) 或 ACCEPT (0x0E)：属于 MMS 初始化阶段
        0x0D | 0x0E => Ok(SessionExtractResult::Init),

        // Session FINISH (0x09) 或 DISCONNECT (0x0A)：属于会话收尾阶段
        0x09 | 0x0A => Ok(SessionExtractResult::SessionClose),

        // Give Tokens (01 00) + Data Transfer (01 00) 模式：跳过 4 字节后进入 Presentation 层
        0x01 => {
            // Give Tokens SPDU: type=0x01, length=0x00 → 2 bytes
            if payload.len() < 4 {
                return Err(());
            }
            if payload[1] != 0x00 {
                return Err(());
            }
            // Data Transfer SPDU: type=0x01, length=0x00 → 2 bytes
            if payload[2] != 0x01 || payload[3] != 0x00 {
                return Err(());
            }
            // Remaining is Presentation layer data
            let pres_data = &payload[4..];
            extract_mms_from_presentation(pres_data).map(|opt| match opt {
                Some(data) => SessionExtractResult::Mms(data),
                // 仅为兼容返回类型；当前实现不会返回 Ok(None)
                None => SessionExtractResult::Init,
            })
        }

        _ => Err(()),
    }
}

/// 从 Presentation 层 fully-encoded-data 中提取 MMS PDU。
/// 遍历 PDV-list，查找 presentation-context-id=3 或 1（MMS 上下文）的条目，
/// 从其 single-ASN1-type [0] 包装中提取实际 MMS 数据。
fn extract_mms_from_presentation(data: &[u8]) -> Result<Option<&[u8]>, ()> {
    if data.is_empty() {
        return Err(());
    }

    // 期望 fully-encoded-data [APPLICATION 1] = 标签 0x61
    let (tag_byte, _, _, fed_content, _) = parse_ber_tlv(data)?;
    if tag_byte != 0x61 {
        return Err(());
    }

    // 遍历 PDV-list 条目（每个是 SEQUENCE 0x30）
    let mut pos = fed_content;
    while !pos.is_empty() {
        // Each PDV-list entry is a SEQUENCE (0x30)
        let (entry_tag, _, _, entry_content, rem) = parse_ber_tlv(pos)?;
        if entry_tag != 0x30 {
            pos = rem;
            continue;
        }

        // 每个 PDV-list 条目内：先读 presentation-context-identifier (INTEGER 0x02)
        if let Ok((id_tag, _, _, id_content, entry_rem)) = parse_ber_tlv(entry_content) {
            if id_tag == 0x02 {
                let ctx_id = parse_ber_integer(id_content).unwrap_or(0);
                if ctx_id == 3 || ctx_id == 1 {
                    // 匹配到 MMS 上下文（通常 id=3，部分实现用 id=1）
                    // 下一个元素是 single-ASN1-type [0] IMPLICIT 包装
                    if let Ok((wrapper_tag, _, _, mms_data, _)) = parse_ber_tlv(entry_rem) {
                        if wrapper_tag == 0xA0 {
                            // This is the MMS PDU
                            return Ok(Some(mms_data));
                        }
                    }
                }
            }
        }

        pos = rem;
    }

    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====== is_direct_mms_pdu 测试 ======

    #[test]
    fn test_is_direct_mms_pdu_constructed() {
        // 0xA0-0xAD 范围识别（constructed 形式）
        for b in 0xA0u8..=0xAD {
            assert!(
                is_direct_mms_pdu(&[b, 0x00]),
                "0x{:02X} should be recognized as direct MMS PDU",
                b
            );
        }
        // 0xAE 超出范围
        assert!(!is_direct_mms_pdu(&[0xAE, 0x00]));
    }

    #[test]
    fn test_is_direct_mms_pdu_primitive() {
        // 0x80-0x8D 范围识别（primitive 形式）
        for b in 0x80u8..=0x8D {
            assert!(
                is_direct_mms_pdu(&[b, 0x00]),
                "0x{:02X} should be recognized as direct MMS PDU",
                b
            );
        }
        // 0x8E 超出范围
        assert!(!is_direct_mms_pdu(&[0x8E, 0x00]));
    }

    #[test]
    fn test_is_direct_mms_pdu_empty() {
        assert!(!is_direct_mms_pdu(&[]));
    }

    #[test]
    fn test_is_direct_mms_pdu_invalid() {
        // 非 MMS 标签
        assert!(!is_direct_mms_pdu(&[0x30, 0x00])); // SEQUENCE
        assert!(!is_direct_mms_pdu(&[0x02, 0x01])); // INTEGER
        assert!(!is_direct_mms_pdu(&[0x61, 0x00])); // APPLICATION 1
        assert!(!is_direct_mms_pdu(&[0x0D, 0x00])); // Session CONNECT
    }

    // ====== extract_mms_from_session 测试 ======

    #[test]
    fn test_extract_session_connect() {
        // SPDU 0x0D → Init
        let payload = [0x0D, 0x00];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Init => {}
            _ => panic!("Expected Init for Session CONNECT"),
        }
    }

    #[test]
    fn test_extract_session_finish() {
        // SPDU 0x09 → SessionClose
        let payload = [0x09, 0x00];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::SessionClose => {}
            _ => panic!("Expected SessionClose for Session FINISH"),
        }
    }

    #[test]
    fn test_extract_session_too_short() {
        // 不足 2 字节应返回 Err
        assert!(extract_mms_from_session(&[]).is_err());
        assert!(extract_mms_from_session(&[0x0D]).is_err());
    }
}
