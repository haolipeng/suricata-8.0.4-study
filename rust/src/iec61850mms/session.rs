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
    /// Session CONNECT/ACCEPT，属于初始化阶段。携带可选的 MMS PDU 载荷。
    Init(Option<&'a [u8]>),
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

/// 解析 Session SPDU 的长度字段（ISO 8327-1 §8.2 Length Encoding）。
/// - 0x00..=0xFE：单字节，直接表示长度值
/// - 0xFF：后续 2 字节大端表示实际长度
/// 返回 (长度值, 消耗的字节数)。
fn parse_session_length(data: &[u8]) -> Result<(usize, usize), ()> {
    if data.is_empty() {
        return Err(());
    }
    if data[0] != 0xFF {
        // 短格式：单字节直接表示长度 (0..=254)
        Ok((data[0] as usize, 1))
    } else {
        // 长格式：0xFF + 2 字节大端
        if data.len() < 3 {
            return Err(());
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    }
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
        // 尝试跳过 Session 头部参数，进入 Presentation 层提取 MMS Initiate PDU
        0x0D | 0x0E => {
            let (session_len, len_size) = parse_session_length(&payload[1..])?;
            let params_start = 1 + len_size;
            let params_end = params_start + session_len;
            if params_end > payload.len() {
                return Ok(SessionExtractResult::Init(None));
            }
            // 遍历 Session 参数列表，查找 Session User Data (0xC1) 参数
            // Presentation 层数据嵌套在该参数内部，而非 Session 头部之后
            let pres_data = find_session_user_data(&payload[params_start..params_end]);
            if let Some(data) = pres_data {
                match extract_mms_from_presentation_init(data) {
                    Ok(Some(mms_data)) => Ok(SessionExtractResult::Init(Some(mms_data))),
                    _ => Ok(SessionExtractResult::Init(None)),
                }
            } else {
                Ok(SessionExtractResult::Init(None))
            }
        }

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
                None => SessionExtractResult::Init(None),
            })
        }

        _ => Err(()),
    }
}

/// 遍历 Session 参数列表（TLV 序列），查找 Session User Data (type=0xC1)。
/// 返回该参数的值部分（即 Presentation 层数据）。
fn find_session_user_data<'a>(params: &'a [u8]) -> Option<&'a [u8]> {
    let mut pos = params;
    while pos.len() >= 2 {
        let param_type = pos[0];
        let (param_len, len_consumed) = match parse_session_length(&pos[1..]) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let value_start = 1 + len_consumed;
        if value_start + param_len > pos.len() {
            return None;
        }
        if param_type == 0xC1 {
            return Some(&pos[value_start..value_start + param_len]);
        }
        pos = &pos[value_start + param_len..];
    }
    None
}

/// 从 Presentation 层 CP-type / CPA-type 中提取 MMS Initiate PDU。
/// CONNECT/ACCEPT 阶段的 Presentation 结构：
///   CP-type/CPA-type (SEQUENCE) → normal-mode-parameters → user-data →
///   fully-encoded-data → PDV-list → context-id=1 → ACSE AARQ/AARE →
///   user-information → EXTERNAL → single-ASN1-type → MMS Initiate PDU
fn extract_mms_from_presentation_init(data: &[u8]) -> Result<Option<&[u8]>, ()> {
    if data.is_empty() {
        return Err(());
    }

    // CP-type 是 [APPLICATION 0] SET = 0x31，CPA-type 也是 0x31
    let (tag_byte, _, _, cp_content, _) = parse_ber_tlv(data)?;
    if tag_byte != 0x31 {
        return Err(());
    }

    // 在 CP-type 中查找 normal-mode-parameters [2] = 0xA2
    let mut pos = cp_content;
    let mut normal_mode = None;
    while !pos.is_empty() {
        let (tag, _, _, inner, rem) = parse_ber_tlv(pos)?;
        if tag == 0xA2 {
            normal_mode = Some(inner);
            break;
        }
        pos = rem;
    }
    let normal_mode = match normal_mode {
        Some(d) => d,
        None => return Err(()),
    };

    // 在 normal-mode-parameters 中查找 user-data [APPLICATION 0] = 0x61
    // (user-data 是 fully-encoded-data)
    pos = normal_mode;
    let mut user_data = None;
    while !pos.is_empty() {
        let (tag, _, _, inner, rem) = parse_ber_tlv(pos)?;
        if tag == 0x61 {
            user_data = Some(inner);
            break;
        }
        pos = rem;
    }
    let user_data = match user_data {
        Some(d) => d,
        None => return Err(()),
    };

    // 遍历 PDV-list 条目，查找 ACSE 上下文 (context-id=1)
    pos = user_data;
    while !pos.is_empty() {
        let (entry_tag, _, _, entry_content, rem) = parse_ber_tlv(pos)?;
        if entry_tag != 0x30 {
            pos = rem;
            continue;
        }
        if let Ok((id_tag, _, _, id_content, entry_rem)) = parse_ber_tlv(entry_content) {
            if id_tag == 0x02 {
                let ctx_id = parse_ber_integer(id_content).unwrap_or(0);
                if ctx_id == 1 {
                    // context-id=1 → ACSE，从 single-ASN1-type [0] 中提取 AARQ/AARE
                    if let Ok((wrapper_tag, _, _, acse_data, _)) = parse_ber_tlv(entry_rem) {
                        if wrapper_tag == 0xA0 {
                            return extract_mms_from_acse(acse_data);
                        }
                    }
                } else if ctx_id == 3 {
                    // context-id=3 → 直接是 MMS（某些实现可能直接放这里）
                    if let Ok((wrapper_tag, _, _, mms_data, _)) = parse_ber_tlv(entry_rem) {
                        if wrapper_tag == 0xA0 {
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

/// 从 ACSE AARQ/AARE PDU 中提取 MMS Initiate PDU。
/// AARQ [APPLICATION 0] = 0x60, AARE [APPLICATION 1] = 0x61
/// user-information [30] IMPLICIT = 0xBE
/// 内含 EXTERNAL (SEQUENCE 0x28):
///   direct-reference (OID) 或 indirect-reference (INTEGER)
///   single-ASN1-type [0] → MMS PDU
fn extract_mms_from_acse(data: &[u8]) -> Result<Option<&[u8]>, ()> {
    if data.is_empty() {
        return Err(());
    }

    // AARQ = 0x60 [APPLICATION 0], AARE = 0x61 [APPLICATION 1]
    let (tag_byte, _, _, acse_content, _) = parse_ber_tlv(data)?;
    if tag_byte != 0x60 && tag_byte != 0x61 {
        return Err(());
    }

    // 遍历 AARQ/AARE 字段，查找 user-information [30] IMPLICIT = 0xBE
    let mut pos = acse_content;
    while !pos.is_empty() {
        let (tag, _, _, inner, rem) = parse_ber_tlv(pos)?;
        if tag == 0xBE {
            // user-information: SEQUENCE OF EXTERNAL
            // 解析 EXTERNAL (SEQUENCE tag=0x28)
            if let Ok((ext_tag, _, _, ext_content, _)) = parse_ber_tlv(inner) {
                if ext_tag == 0x28 {
                    return extract_mms_from_external(ext_content);
                }
            }
            return Err(());
        }
        pos = rem;
    }

    Err(())
}

/// 从 EXTERNAL (Association-data) 中提取 MMS PDU。
/// EXTERNAL 结构：
///   direct-reference INTEGER (context-id=3 表示 MMS)
///   single-ASN1-type [0] → MMS PDU
fn extract_mms_from_external(data: &[u8]) -> Result<Option<&[u8]>, ()> {
    let mut pos = data;
    while !pos.is_empty() {
        let (tag, _, _, inner, rem) = parse_ber_tlv(pos)?;
        if tag == 0xA0 {
            // single-ASN1-type [0] → 内部就是 MMS PDU
            return Ok(Some(inner));
        }
        pos = rem;
    }
    Err(())
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
            SessionExtractResult::Init(_) => {}
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

    // ====== parse_session_length 测试 ======

    #[test]
    fn test_parse_session_length_short() {
        // 短格式：0x00..=0xFE 直接表示长度
        assert_eq!(parse_session_length(&[0x00]).unwrap(), (0, 1));
        assert_eq!(parse_session_length(&[0x05]).unwrap(), (5, 1));
        assert_eq!(parse_session_length(&[0xFE]).unwrap(), (254, 1));
    }

    #[test]
    fn test_parse_session_length_long() {
        // 长格式：0xFF + 2字节大端
        assert_eq!(parse_session_length(&[0xFF, 0x00, 0xFF]).unwrap(), (255, 3));
        assert_eq!(parse_session_length(&[0xFF, 0x01, 0x00]).unwrap(), (256, 3));
    }

    #[test]
    fn test_parse_session_length_long_truncated() {
        // 长格式但数据不足 → Err
        assert!(parse_session_length(&[0xFF]).is_err());
        assert!(parse_session_length(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_parse_session_length_empty() {
        assert!(parse_session_length(&[]).is_err());
    }

    #[test]
    fn test_extract_session_connect_long_length() {
        // CONNECT SPDU 使用长格式长度：0xFF + 2字节 = 参数长度3
        // 参数内容为 3 字节填充，之后无 Presentation 层数据
        let payload = [0x0D, 0xFF, 0x00, 0x03, 0x00, 0x00, 0x00];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Init(None) => {}
            other => panic!("Expected Init(None), got {:?}", std::mem::discriminant(&other)),
        }
    }

    // ====== Give Tokens + Data Transfer 边界测试 ======

    #[test]
    fn test_give_tokens_too_short() {
        // Give Tokens 类型但不足 4 字节 → Err
        assert!(extract_mms_from_session(&[0x01, 0x00, 0x01]).is_err());
        assert!(extract_mms_from_session(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_give_tokens_bad_gt_length() {
        // Give Tokens length != 0x00 → Err
        let payload = [0x01, 0x01, 0x01, 0x00];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_give_tokens_bad_dt_type() {
        // Data Transfer type != 0x01 → Err
        let payload = [0x01, 0x00, 0x02, 0x00];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_give_tokens_bad_dt_length() {
        // Data Transfer length != 0x00 → Err
        let payload = [0x01, 0x00, 0x01, 0x01];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_give_tokens_no_presentation_data() {
        // Give Tokens + Data Transfer 正确，但无后续 Presentation 数据 → Err
        // (extract_mms_from_presentation 对空输入返回 Err)
        let payload = [0x01, 0x00, 0x01, 0x00];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_session_disconnect() {
        // DISCONNECT (0x0A) → SessionClose
        let payload = [0x0A, 0x00];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::SessionClose => {}
            _ => panic!("Expected SessionClose for Session DISCONNECT"),
        }
    }

    #[test]
    fn test_session_unknown_spdu_type() {
        // 未知 SPDU 类型 → Err
        assert!(extract_mms_from_session(&[0x55, 0x00]).is_err());
        assert!(extract_mms_from_session(&[0x30, 0x00]).is_err());
    }

    // ====== Presentation 层测试 ======

    #[test]
    fn test_presentation_non_mms_context_skipped() {
        // PDV-list 有一个条目 context-id=5（非 MMS），后跟一个 context-id=3（MMS）
        // 应跳过 id=5，找到 id=3 并提取 MMS 数据
        let payload = [
            0x01, 0x00, 0x01, 0x00, // Give Tokens + Data Transfer
            0x61, 0x16,             // fully-encoded-data [APPLICATION 1], length=22
            // PDV-list entry 1: context-id=5 (非 MMS, 应跳过)
            0x30, 0x08,             // SEQUENCE, length=8
            0x02, 0x01, 0x05,       // INTEGER context-id=5
            0xA0, 0x03,             // [0] single-ASN1-type wrapper, length=3
            0x30, 0x01, 0x00,       // 某些其他数据
            // PDV-list entry 2: context-id=3 (MMS)
            0x30, 0x0A,             // SEQUENCE, length=10
            0x02, 0x01, 0x03,       // INTEGER context-id=3
            0xA0, 0x05,             // [0] single-ASN1-type wrapper, length=5
            0xA8, 0x03, 0x80, 0x01, 0x01, // MMS Initiate-Request
        ];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Mms(data) => {
                // 提取到的应是 MMS Initiate-Request
                assert_eq!(data[0], 0xA8);
            }
            other => panic!("Expected Mms, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_presentation_context_id_1() {
        // 某些实现使用 context-id=1 作为 MMS 上下文
        let payload = [
            0x01, 0x00, 0x01, 0x00, // Give Tokens + Data Transfer
            0x61, 0x0C,             // fully-encoded-data
            0x30, 0x0A,             // SEQUENCE
            0x02, 0x01, 0x01,       // INTEGER context-id=1
            0xA0, 0x05,             // [0] wrapper
            0xAB, 0x03, 0x80, 0x01, 0x00, // MMS Conclude-Request (with content)
        ];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Mms(data) => {
                assert_eq!(data[0], 0xAB); // Conclude-Request tag
            }
            _ => panic!("Expected Mms"),
        }
    }

    #[test]
    fn test_presentation_no_mms_context() {
        // 所有 PDV-list 条目都不是 MMS context (id != 1 和 != 3) → Err
        let payload = [
            0x01, 0x00, 0x01, 0x00,
            0x61, 0x08,
            0x30, 0x06,
            0x02, 0x01, 0x05,       // context-id=5
            0xA0, 0x01, 0x00,
        ];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_presentation_bad_tag() {
        // 顶层不是 [APPLICATION 1] (0x61) → Err
        let payload = [
            0x01, 0x00, 0x01, 0x00,
            0x30, 0x06,             // SEQUENCE 而非 APPLICATION 1
            0x30, 0x04,
            0x02, 0x01, 0x03,
            0x00,
        ];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_presentation_wrapper_not_a0() {
        // context-id=3 匹配，但 wrapper tag 不是 0xA0 → 跳过该条目 → Err
        let payload = [
            0x01, 0x00, 0x01, 0x00,
            0x61, 0x08,
            0x30, 0x06,
            0x02, 0x01, 0x03,       // context-id=3
            0xA1, 0x01, 0x00,       // wrapper tag=0xA1 (不是 0xA0)
        ];
        assert!(extract_mms_from_session(&payload).is_err());
    }

    #[test]
    fn test_session_accept() {
        // ACCEPT (0x0E) 与 CONNECT 走相同逻辑，验证 Init 路径
        let payload = [0x0E, 0x00];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Init(_) => {}
            _ => panic!("Expected Init for Session ACCEPT"),
        }
    }

    #[test]
    fn test_session_connect_with_presentation() {
        // 真实的 CONNECT SPDU，Presentation 层数据在 Session User Data (0xC1) 参数内
        // 完整的封装路径：Session → C1(User Data) → CP-type(0x31) →
        //   normal-mode-parameters(0xA2) → user-data(0x61) → PDV-list →
        //   context-id=1(ACSE) → AARQ(0x60) → user-information(0xBE) →
        //   EXTERNAL(0x28) → single-ASN1-type(0xA0) → MMS Initiate-Request
        //
        // 从 mms.pcap 第 7 包提取的 COTP payload:
        let payload = [
            0x0D, 0x9E, // CONNECT SPDU, length=158
            // Session 参数:
            0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, // Connect Accept Item
            0x14, 0x02, 0x00, 0x02, // Session Requirement
            0x33, 0x02, 0x00, 0x01, // Calling Session Selector
            0x34, 0x02, 0x00, 0x01, // Called Session Selector
            // Session User Data (0xC1), length=0x88=136
            0xC1, 0x88,
            // CP-type (SET, 0x31)
            0x31, 0x81, 0x85,
            // mode-selector [0]
            0xA0, 0x03, 0x80, 0x01, 0x01,
            // normal-mode-parameters [2]
            0xA2, 0x7E,
            // calling-presentation-selector
            0x81, 0x04, 0x00, 0x00, 0x00, 0x01,
            // called-presentation-selector
            0x82, 0x04, 0x00, 0x00, 0x00, 0x01,
            // presentation-context-definition-list
            0xA4, 0x23,
            0x30, 0x0F, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01,
            0x30, 0x04, 0x06, 0x02, 0x51, 0x01,
            0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x01,
            0x30, 0x04, 0x06, 0x02, 0x51, 0x01,
            // presentation-requirements
            0x88, 0x02, 0x06, 0x00,
            // user-data: fully-encoded-data [APPLICATION 1] = 0x61
            0x61, 0x47,
            0x30, 0x45, 0x02, 0x01, 0x01, // PDV-list, context-id=1
            0xA0, 0x40, // single-ASN1-type [0]
            // ACSE AARQ [APPLICATION 0] = 0x60
            0x60, 0x3E,
            0x80, 0x02, 0x07, 0x80, // protocol-version
            0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03, // aSO-context-name
            // user-information [30] IMPLICIT = 0xBE
            0xBE, 0x2F,
            // EXTERNAL (0x28)
            0x28, 0x2D,
            0x02, 0x01, 0x03, // direct-reference = 3
            // single-ASN1-type [0]
            0xA0, 0x28,
            // MMS Initiate-Request [8] = 0xA8
            0xA8, 0x26,
            0x80, 0x03, 0x00, 0xFA, 0x00, // localDetailCalling = 64000
            0x81, 0x01, 0x0A,             // maxServOutstandingCalling = 10
            0x82, 0x01, 0x0A,             // maxServOutstandingCalled = 10
            0x83, 0x01, 0x05,             // dataStructureNestingLevel = 5
            0xA4, 0x16,                   // initRequestDetail
            0x80, 0x01, 0x01,             // versionNumber = 1
            0x81, 0x03, 0x05, 0xE1, 0x00, // parameterCBB
            0x82, 0x0C, 0x03, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE1, 0x10,
        ];
        match extract_mms_from_session(&payload).unwrap() {
            SessionExtractResult::Init(Some(data)) => {
                assert_eq!(data[0], 0xA8); // MMS Initiate-Request tag
                assert_eq!(data.len(), 40); // MMS Initiate-Request 的完整 TLV (A8 26 + 38字节内容)
            }
            other => panic!("Expected Init(Some), got {:?}", std::mem::discriminant(&other)),
        }
    }
}
