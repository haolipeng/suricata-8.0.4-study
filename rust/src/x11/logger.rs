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

//! EVE JSON logger for X11 transactions.

use super::parser::X11SetupResponse;
use super::x11::X11Transaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_x11(tx: &X11Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("x11")?;

    // Setup information
    js.open_object("setup")?;
    js.set_string("version", &tx.version_string)?;

    if let Some(ref req) = tx.setup_request {
        if !req.auth_protocol_name.is_empty() {
            js.set_string("auth_protocol", &req.auth_protocol_name)?;
        }
    }

    if let Some(ref resp) = tx.setup_response {
        match resp {
            X11SetupResponse::Success {
                release_number,
                vendor,
                screen_count,
                ..
            } => {
                js.set_string("status", "success")?;
                if !vendor.is_empty() {
                    js.set_string("vendor", vendor)?;
                }
                js.set_uint("release_number", *release_number as u64)?;
                js.set_uint("screen_count", *screen_count as u64)?;
            }
            X11SetupResponse::Failed { reason, .. } => {
                js.set_string("status", "failed")?;
                if !reason.is_empty() {
                    js.set_string("reason", reason)?;
                }
            }
            X11SetupResponse::Authenticate { reason } => {
                js.set_string("status", "authenticate")?;
                if !reason.is_empty() {
                    js.set_string("reason", reason)?;
                }
            }
        }
    }
    js.close()?; // setup

    // Request statistics
    js.open_object("requests")?;
    js.set_uint("total_count", tx.request_total_count)?;
    if !tx.request_opcodes.is_empty() {
        js.open_object("opcodes")?;
        // Sort by opcode name for deterministic output
        let mut opcodes: Vec<_> = tx.request_opcodes.iter().collect();
        opcodes.sort_by_key(|(k, _)| *k);
        for (name, count) in opcodes {
            js.set_uint(name, *count)?;
        }
        js.close()?; // opcodes
    }
    js.close()?; // requests

    // Response statistics
    js.open_object("responses")?;
    js.set_uint("reply_count", tx.reply_count)?;
    js.set_uint("event_count", tx.event_count)?;
    js.set_uint("error_count", tx.error_count)?;
    if !tx.errors.is_empty() {
        js.open_array("errors")?;
        for err in &tx.errors {
            js.start_object()?;
            js.set_uint("code", err.code as u64)?;
            js.set_string("name", err.name)?;
            js.close()?;
        }
        js.close()?; // errors
    }
    js.close()?; // responses

    js.close()?; // x11
    Ok(())
}

/// C callback: Suricata logging framework calls this to output transaction JSON.
#[no_mangle]
pub unsafe extern "C" fn SCX11LoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, X11Transaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_x11(tx, js).is_ok()
}
