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

//! Detection keyword registration for X11.
//!
//! Registers sticky buffer:
//! - `x11.version` - matches on the X11 version string (e.g. "11.0")

use super::x11::{X11Transaction, ALPROTO_X11};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_X11_VERSION_BUFFER_ID: c_int = 0;

/// Setup callback for x11.version keyword
unsafe extern "C" fn x11_version_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_X11) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_X11_VERSION_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

/// Get version string from transaction for content matching
unsafe extern "C" fn x11_version_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, X11Transaction);
    if !tx.version_string.is_empty() {
        *len = tx.version_string.len() as u32;
        *buf = tx.version_string.as_ptr();
        return true;
    }
    false
}

/// Register x11.version sticky buffer keyword with Suricata detection engine.
#[no_mangle]
pub unsafe extern "C" fn SCDetectX11Register() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("x11.version"),
        desc: String::from("X11 protocol version content modifier"),
        url: String::from("/rules/x11-keywords.html#version"),
        setup: x11_version_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_X11_VERSION_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"x11.version\0".as_ptr() as *const libc::c_char,
        b"X11 protocol version\0".as_ptr() as *const libc::c_char,
        ALPROTO_X11,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(x11_version_get),
    );
}
