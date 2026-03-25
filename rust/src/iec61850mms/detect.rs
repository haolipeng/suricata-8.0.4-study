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

use super::mms::{MmsTransaction, ALPROTO_IEC61850_MMS};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use crate::direction::Direction;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_IEC61850_MMS_SERVICE_BUFFER_ID: c_int = 0;
static mut G_IEC61850_MMS_PDU_TYPE_BUFFER_ID: c_int = 0;

// --- iec61850_mms.service keyword ---

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

/// Get the service name buffer for a transaction.
unsafe extern "C" fn iec61850_mms_service_get(
    tx: *const c_void, flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let pdu = if flags & Direction::ToClient as u8 != 0 {
        tx.response.as_ref()
    } else {
        tx.request.as_ref()
    };
    if let Some(pdu) = pdu {
        if let Some(service) = pdu.service_str() {
            *len = service.len() as u32;
            *buf = service.as_ptr();
            return true;
        }
    }
    return false;
}

// --- iec61850_mms.pdu_type keyword ---

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

/// Get the PDU type buffer for a transaction.
unsafe extern "C" fn iec61850_mms_pdu_type_get(
    tx: *const c_void, flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let pdu = if flags & Direction::ToClient as u8 != 0 {
        tx.response.as_ref()
    } else {
        tx.request.as_ref()
    };
    if let Some(pdu) = pdu {
        let pdu_type = pdu.pdu_type_str();
        *len = pdu_type.len() as u32;
        *buf = pdu_type.as_ptr();
        return true;
    }
    return false;
}

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
}
