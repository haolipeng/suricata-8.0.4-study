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
use super::mms_types::{MmsPdu, ObjectNameRef};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

/// 将 ObjectNameRef 写入 JSON。
fn log_object_name_ref(name: &ObjectNameRef, js: &mut JsonBuilder) -> Result<(), JsonError> {
    match name {
        ObjectNameRef::VmdSpecific(id) => {
            js.set_string("scope", "vmd_specific")?;
            js.set_string("item", id)?;
        }
        ObjectNameRef::DomainSpecific { domain_id, item_id } => {
            js.set_string("scope", "domain_specific")?;
            js.set_string("domain", domain_id)?;
            js.set_string("item", item_id)?;
        }
        ObjectNameRef::AaSpecific(id) => {
            js.set_string("scope", "aa_specific")?;
            js.set_string("item", id)?;
        }
    }
    Ok(())
}

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
            get_var_access_attr_info,
            get_named_var_list_attr_info,
            ..
        } => {
            if let Some(ref ri) = read_info {
                if !ri.variable_specs.is_empty() {
                    js.open_array("variables")?;
                    for spec in &ri.variable_specs {
                        js.start_object()?;
                        log_object_name_ref(spec, js)?;
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
                        log_object_name_ref(spec, js)?;
                        js.close()?;
                    }
                    js.close()?;
                }
            }
            if let Some(ref gnl) = get_name_list_info {
                if let Some(ref class) = gnl.object_class {
                    js.set_string("object_class", class)?;
                }
                if let Some(ref scope) = gnl.object_scope {
                    js.set_string("object_scope", scope)?;
                }
                if let Some(ref domain) = gnl.domain_id {
                    js.set_string("domain", domain)?;
                }
                if let Some(ref cont) = gnl.continue_after {
                    js.set_string("continue_after", cont)?;
                }
            }
            if let Some(ref gva) = get_var_access_attr_info {
                if let Some(ref name) = gva.object_name {
                    js.open_object("variable")?;
                    log_object_name_ref(name, js)?;
                    js.close()?;
                }
            }
            if let Some(ref gnvla) = get_named_var_list_attr_info {
                if let Some(ref name) = gnvla.object_name {
                    js.open_object("object_name")?;
                    log_object_name_ref(name, js)?;
                    js.close()?;
                }
            }
        }
        MmsPdu::ConfirmedResponse {
            get_name_list_info,
            get_named_var_list_attr_info,
            read_info,
            get_var_access_attr_info,
            ..
        } => {
            if let Some(ref gnl) = get_name_list_info {
                if !gnl.identifiers.is_empty() {
                    js.open_array("identifiers")?;
                    for id in &gnl.identifiers {
                        js.append_string(id)?;
                    }
                    js.close()?;
                }
                js.set_bool("more_follows", gnl.more_follows)?;
            }
            if let Some(ref gnvla) = get_named_var_list_attr_info {
                js.set_bool("mms_deletable", gnvla.mms_deletable)?;
                if !gnvla.variables.is_empty() {
                    js.set_uint("variable_count", gnvla.variables.len() as u64)?;
                    js.open_array("variables")?;
                    for var in &gnvla.variables {
                        js.start_object()?;
                        log_object_name_ref(var, js)?;
                        js.close()?;
                    }
                    js.close()?;
                }
            }
            if let Some(ref ri) = read_info {
                js.set_uint("result_count", ri.results.len() as u64)?;
                js.open_array("results")?;
                for r in &ri.results {
                    js.start_object()?;
                    js.set_bool("success", r.success)?;
                    if let Some(ref dt) = r.data_type {
                        js.set_string("data_type", dt)?;
                    }
                    if let Some(ref v) = r.value {
                        js.set_string("value", v)?;
                    }
                    js.close()?;
                }
                js.close()?;
            }
            if let Some(ref gva) = get_var_access_attr_info {
                js.set_bool("mms_deletable", gva.mms_deletable)?;
                if let Some(ref td) = gva.type_description {
                    js.set_string("type_description", td)?;
                }
            }
        }
        MmsPdu::ConfirmedError { error_class, error_code, .. } => {
            if let Some(ref ec) = error_class {
                js.set_string("error_class", ec)?;
            }
            if let Some(ref code) = error_code {
                js.set_string("error_code", code)?;
            }
        }
        MmsPdu::InitiateRequest { detail, .. } | MmsPdu::InitiateResponse { detail, .. } => {
            if let Some(ref d) = detail {
                if let Some(v) = d.local_detail {
                    js.set_uint("local_detail", v as u64)?;
                }
                if let Some(v) = d.max_serv_outstanding_calling {
                    js.set_uint("max_serv_outstanding_calling", v as u64)?;
                }
                if let Some(v) = d.max_serv_outstanding_called {
                    js.set_uint("max_serv_outstanding_called", v as u64)?;
                }
                if let Some(v) = d.data_structure_nesting_level {
                    js.set_uint("data_structure_nesting_level", v as u64)?;
                }
                if let Some(v) = d.version_number {
                    js.set_uint("version_number", v as u64)?;
                }
                if let Some(ref svc) = d.supported_services {
                    let hex: String = svc.iter().map(|b| format!("{:02x}", b)).collect();
                    js.set_string("supported_services", &hex)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// 输出一个事务的完整 EVE JSON 日志：iec61850_mms { direction: "...", pdu_type: "...", ... }
fn log_iec61850_mms(tx: &MmsTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("iec61850_mms")?;
    js.set_string("direction", if tx.is_request { "request" } else { "response" })?;
    if let Some(ref pdu) = tx.pdu {
        log_mms_pdu(pdu, js)?;
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
