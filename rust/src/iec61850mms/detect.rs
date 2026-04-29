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

//! Detection keyword registration for IEC 61850 MMS.
//!
//! Registers sticky buffers:
//! - `iec61850_mms.service` - matches on the service name string
//! - `iec61850_mms.pdu_type` - matches on the PDU type string
//! - `iec61850_mms.write_variable` - matches on Write request variable names (multi-buffer)
//! - `iec61850_mms.write_domain` - matches on Write request domain names (multi-buffer)

use super::mms::{MmsTransaction, ALPROTO_IEC61850_MMS};
use super::mms_types::{MmsPdu, ObjectNameRef};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperMultiBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

// Sticky buffer ID，由检测引擎分配，用于在规则中引用对应的内容缓冲区
static mut G_IEC61850_MMS_SERVICE_BUFFER_ID: c_int = 0;
static mut G_IEC61850_MMS_PDU_TYPE_BUFFER_ID: c_int = 0;
static mut G_IEC61850_MMS_WRITE_VARIABLE_BUFFER_ID: c_int = 0;
static mut G_IEC61850_MMS_WRITE_DOMAIN_BUFFER_ID: c_int = 0;

// --- iec61850_mms.service keyword ---

/// 规则中使用该关键字时的 setup 回调：绑定协议和激活对应 buffer
unsafe extern "C" fn iec61850_mms_service_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC61850_MMS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC61850_MMS_SERVICE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// 获取事务中的服务名称字符串，供检测引擎进行内容匹配。
/// flags 的 Direction 位决定取请求侧还是响应侧的 PDU。
unsafe extern "C" fn iec61850_mms_service_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    if let Some(ref pdu) = tx.pdu {
        if let Some(service) = pdu.service_str() {
            *len = service.len() as u32;
            *buf = service.as_ptr();
            return true;
        }
    }
    return false;
}

// --- iec61850_mms.pdu_type keyword ---

/// pdu_type 关键字的 setup 回调
unsafe extern "C" fn iec61850_mms_pdu_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC61850_MMS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC61850_MMS_PDU_TYPE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// 获取事务中的 PDU 类型字符串，供检测引擎进行内容匹配
unsafe extern "C" fn iec61850_mms_pdu_type_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    if let Some(ref pdu) = tx.pdu {
        let pdu_type = pdu.pdu_type_str();
        *len = pdu_type.len() as u32;
        *buf = pdu_type.as_ptr();
        return true;
    }
    return false;
}

// --- iec61850_mms.write_variable keyword ---

/// write_variable 关键字的 setup 回调
unsafe extern "C" fn iec61850_mms_write_variable_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC61850_MMS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC61850_MMS_WRITE_VARIABLE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// 获取 Write 请求中第 local_id 个变量名，供检测引擎进行内容匹配。
/// 检测引擎从 local_id=0 开始递增调用，直到返回 false。
unsafe extern "C" fn iec61850_mms_write_variable_get(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void, _flags: u8, local_id: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    if let Some(ref pdu) = tx.pdu {
        if let MmsPdu::ConfirmedRequest { write_info: Some(ref wi), .. } = pdu {
            if let Some(spec) = wi.variable_specs.get(local_id as usize) {
                let var_name = match spec {
                    ObjectNameRef::VmdSpecific(s) => s.as_str(),
                    ObjectNameRef::DomainSpecific { item_id, .. } => item_id.as_str(),
                    ObjectNameRef::AaSpecific(s) => s.as_str(),
                };
                *len = var_name.len() as u32;
                *buf = var_name.as_ptr();
                return true;
            }
        }
    }
    *buf = ptr::null();
    *len = 0;
    return false;
}

// --- iec61850_mms.write_domain keyword ---

/// write_domain 关键字的 setup 回调
unsafe extern "C" fn iec61850_mms_write_domain_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC61850_MMS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC61850_MMS_WRITE_DOMAIN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// 获取 Write 请求中第 local_id 个变量的 domain 名称，供检测引擎进行内容匹配。
/// 仅 DomainSpecific 变量有 domain；VmdSpecific/AaSpecific 跳过（返回 false），
/// 引擎会继续尝试下一个 local_id。
unsafe extern "C" fn iec61850_mms_write_domain_get(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void, _flags: u8, local_id: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    if let Some(ref pdu) = tx.pdu {
        if let MmsPdu::ConfirmedRequest { write_info: Some(ref wi), .. } = pdu {
            if let Some(ObjectNameRef::DomainSpecific { domain_id, .. }) =
                wi.variable_specs.get(local_id as usize)
            {
                *len = domain_id.len() as u32;
                *buf = domain_id.as_ptr();
                return true;
            }
        }
    }
    *buf = ptr::null();
    *len = 0;
    return false;
}

/// 向 Suricata 检测引擎注册 sticky buffer 关键字：
/// - iec61850_mms.service：匹配 MMS 服务名称（如 "read"、"write"）
/// - iec61850_mms.pdu_type：匹配 PDU 类型（如 "confirmed_request"）
/// - iec61850_mms.write_variable：匹配 Write 请求变量名（multi-buffer，逐个匹配）
/// - iec61850_mms.write_domain：匹配 Write 请求变量的 domain（multi-buffer，逐个匹配）
#[no_mangle]
pub unsafe extern "C" fn SCDetectIec61850MmsRegister() {
    // Register iec61850_mms.service sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec61850_mms.service"),
        desc: String::from("IEC 61850 MMS service name content modifier"),
        url: String::from("/rules/iec61850-mms-keywords.html#service"),
        setup: iec61850_mms_service_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC61850_MMS_SERVICE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec61850_mms.service\0".as_ptr() as *const libc::c_char,
        b"IEC 61850 MMS service name\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC61850_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec61850_mms_service_get),
    );

    // Register iec61850_mms.pdu_type sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec61850_mms.pdu_type"),
        desc: String::from("IEC 61850 MMS PDU type content modifier"),
        url: String::from("/rules/iec61850-mms-keywords.html#pdu-type"),
        setup: iec61850_mms_pdu_type_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC61850_MMS_PDU_TYPE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec61850_mms.pdu_type\0".as_ptr() as *const libc::c_char,
        b"IEC 61850 MMS PDU type\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC61850_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec61850_mms_pdu_type_get),
    );

    // Register iec61850_mms.write_variable sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec61850_mms.write_variable"),
        desc: String::from("IEC 61850 MMS Write request variable name"),
        url: String::from("/rules/iec61850-mms-keywords.html#write-variable"),
        setup: iec61850_mms_write_variable_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC61850_MMS_WRITE_VARIABLE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"iec61850_mms.write_variable\0".as_ptr() as *const libc::c_char,
        b"IEC 61850 MMS Write variable name\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC61850_MMS,
        STREAM_TOSERVER,
        Some(iec61850_mms_write_variable_get),
    );

    // Register iec61850_mms.write_domain sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec61850_mms.write_domain"),
        desc: String::from("IEC 61850 MMS Write request domain name"),
        url: String::from("/rules/iec61850-mms-keywords.html#write-domain"),
        setup: iec61850_mms_write_domain_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC61850_MMS_WRITE_DOMAIN_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"iec61850_mms.write_domain\0".as_ptr() as *const libc::c_char,
        b"IEC 61850 MMS Write domain name\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC61850_MMS,
        STREAM_TOSERVER,
        Some(iec61850_mms_write_domain_get),
    );
}
