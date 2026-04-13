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

//! EVE JSON logger for IEC 61850 MMS transactions.

use super::mms::MmsTransaction;
use super::mms_pdu::MmsPdu;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

/// 将单个 MMS PDU 写入 JSON：pdu_type、invoke_id、service，
/// 以及 Read/Write 的 variables 数组和 GetNameList 的 object_class/domain。
fn log_mms_pdu(pdu: &MmsPdu, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("pdu_type", pdu.pdu_type_str())?;

    if let Some(invoke_id) = pdu.invoke_id() {
        js.set_uint("invoke_id", invoke_id as u64)?;
    }

    if let Some(service) = pdu.service_str() {
        js.set_string("service", service)?;
    }

    // Log additional details for specific PDU types
    match pdu {
        MmsPdu::ConfirmedRequest {
            read_info,
            write_info,
            get_name_list_info,
            ..
        } => {
            if let Some(ref ri) = read_info {
                if !ri.variable_specs.is_empty() {
                    js.open_array("variables")?;
                    for spec in &ri.variable_specs {
                        js.start_object()?;
                        js.set_string("domain", &spec.domain_id)?;
                        js.set_string("item", &spec.item_id)?;
                        js.close()?;
                    }
                    js.close()?;
                }
            }
            if let Some(ref wi) = write_info {
                if !wi.variable_specs.is_empty() {
                    js.open_array("variables")?;
                    for spec in &wi.variable_specs {
                        js.start_object()?;
                        js.set_string("domain", &spec.domain_id)?;
                        js.set_string("item", &spec.item_id)?;
                        js.close()?;
                    }
                    js.close()?;
                }
            }
            if let Some(ref gnl) = get_name_list_info {
                if let Some(ref class) = gnl.object_class {
                    js.set_string("object_class", class)?;
                }
                if let Some(ref domain) = gnl.domain_id {
                    js.set_string("domain", domain)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// 输出一个事务的完整 EVE JSON 日志：iec61850_mms { request: {...}, response: {...} }
fn log_iec61850_mms(tx: &MmsTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("iec61850_mms")?;

    if let Some(ref request) = tx.request {
        js.open_object("request")?;
        log_mms_pdu(request, js)?;
        js.close()?;
    }

    if let Some(ref response) = tx.response {
        js.open_object("response")?;
        log_mms_pdu(response, js)?;
        js.close()?;
    }

    js.close()?;
    Ok(())
}

/// C 回调入口：Suricata 日志框架调用此函数输出事务的 JSON 日志
#[no_mangle]
pub unsafe extern "C" fn SCIec61850MmsLoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_iec61850_mms(tx, js).is_ok()
}
