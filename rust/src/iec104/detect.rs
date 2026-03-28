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

//! Detection keyword registration for IEC 60870-5-104.
//!
//! Registers sticky buffers:
//! - `iec104.frame_type` - matches on frame type string ("I", "S", "U")
//! - `iec104.typeid` - matches on ASDU type ID string (e.g. "M_SP_NA_1")
//! - `iec104.cot` - matches on cause of transmission string (e.g. "spontaneous")

use super::iec104::{Iec104Transaction, ALPROTO_IEC104};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_IEC104_FRAME_TYPE_BUFFER_ID: c_int = 0;
static mut G_IEC104_TYPEID_BUFFER_ID: c_int = 0;
static mut G_IEC104_COT_BUFFER_ID: c_int = 0;

// --- iec104.frame_type keyword ---

unsafe extern "C" fn iec104_frame_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC104_FRAME_TYPE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn iec104_frame_type_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let frame_type = tx.apci.frame_type_str();
    *len = frame_type.len() as u32;
    *buf = frame_type.as_ptr();
    return true;
}

// --- iec104.typeid keyword ---

unsafe extern "C" fn iec104_typeid_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC104_TYPEID_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn iec104_typeid_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    if let Some(ref asdu) = tx.asdu {
        let type_name = asdu.type_id.as_str();
        *len = type_name.len() as u32;
        *buf = type_name.as_ptr();
        return true;
    }
    return false;
}

// --- iec104.cot keyword ---

unsafe extern "C" fn iec104_cot_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC104_COT_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn iec104_cot_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    if let Some(ref asdu) = tx.asdu {
        let cause_name = asdu.cot.cause_str();
        *len = cause_name.len() as u32;
        *buf = cause_name.as_ptr();
        return true;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectIec104Register() {
    // Register iec104.frame_type sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec104.frame_type"),
        desc: String::from("IEC 104 frame type content modifier"),
        url: String::from("/rules/iec104-keywords.html#frame-type"),
        setup: iec104_frame_type_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC104_FRAME_TYPE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec104.frame_type\0".as_ptr() as *const libc::c_char,
        b"IEC 104 frame type\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC104,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec104_frame_type_get),
    );

    // Register iec104.typeid sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec104.typeid"),
        desc: String::from("IEC 104 ASDU type ID content modifier"),
        url: String::from("/rules/iec104-keywords.html#typeid"),
        setup: iec104_typeid_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC104_TYPEID_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec104.typeid\0".as_ptr() as *const libc::c_char,
        b"IEC 104 ASDU type ID\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC104,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec104_typeid_get),
    );

    // Register iec104.cot sticky buffer
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec104.cot"),
        desc: String::from("IEC 104 cause of transmission content modifier"),
        url: String::from("/rules/iec104-keywords.html#cot"),
        setup: iec104_cot_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_IEC104_COT_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec104.cot\0".as_ptr() as *const libc::c_char,
        b"IEC 104 cause of transmission\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC104,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec104_cot_get),
    );
}
