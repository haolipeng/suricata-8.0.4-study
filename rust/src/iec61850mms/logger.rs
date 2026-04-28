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
                    js.open_array("write_variables")?;
                    for spec in &wi.variable_specs {
                        js.start_object()?;
                        log_object_name_ref(spec, js)?;
                        js.close()?;
                    }
                    js.close()?;
                }
                if !wi.data.is_empty() {
                    js.open_array("write_data")?;
                    for d in &wi.data {
                        js.start_object()?;
                        if let Some(ref dt) = d.data_type {
                            js.set_string("data_type", dt)?;
                        }
                        if let Some(ref v) = d.value {
                            js.set_string("value", v)?;
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec61850mms::mms_types::*;

    /// Helper: call log_mms_pdu and return the JSON string via Debug output.
    fn log_pdu_to_debug_string(pdu: &MmsPdu) -> String {
        let mut js = JsonBuilder::try_new_object().unwrap();
        log_mms_pdu(pdu, &mut js).expect("log_mms_pdu should not fail");
        js.close().unwrap();
        format!("{:?}", js)
    }

    #[test]
    fn test_log_write_request_single_variable_with_data() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::Write,
            read_info: None,
            write_info: Some(MmsWriteRequest {
                variable_specs: vec![ObjectNameRef::DomainSpecific {
                    domain_id: "LLN0".to_string(),
                    item_id: "Mod".to_string(),
                }],
                data: vec![MmsAccessResult {
                    success: true,
                    data_type: Some("boolean".to_string()),
                    value: Some("true".to_string()),
                }],
            }),
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
        };
        let debug = log_pdu_to_debug_string(&pdu);
        // Verify write_variables is present (not just "variables")
        assert!(debug.contains("write_variables"), "should contain write_variables, got: {}", debug);
        assert!(debug.contains("write_data"), "should contain write_data, got: {}", debug);
        assert!(debug.contains("LLN0"), "should contain domain LLN0");
        assert!(debug.contains("boolean"), "should contain data_type boolean");
        assert!(debug.contains("true"), "should contain value true");
    }

    #[test]
    fn test_log_write_request_multiple_variables_and_data() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 2,
            service: MmsConfirmedService::Write,
            read_info: None,
            write_info: Some(MmsWriteRequest {
                variable_specs: vec![
                    ObjectNameRef::DomainSpecific {
                        domain_id: "IED1_LD0".to_string(),
                        item_id: "XCBR1$CO$Pos".to_string(),
                    },
                    ObjectNameRef::VmdSpecific("GlobalVar".to_string()),
                ],
                data: vec![
                    MmsAccessResult {
                        success: true,
                        data_type: Some("structure".to_string()),
                        value: Some("4 items".to_string()),
                    },
                    MmsAccessResult {
                        success: true,
                        data_type: Some("integer".to_string()),
                        value: Some("42".to_string()),
                    },
                ],
            }),
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
        };
        let debug = log_pdu_to_debug_string(&pdu);
        // 两个变量
        assert!(debug.contains("IED1_LD0"), "should contain domain IED1_LD0");
        assert!(debug.contains("XCBR1$CO$Pos"), "should contain item XCBR1$CO$Pos");
        assert!(debug.contains("GlobalVar"), "should contain vmd_specific GlobalVar");
        // 两个数据
        assert!(debug.contains("structure"), "should contain data_type structure");
        assert!(debug.contains("4 items"), "should contain value 4 items");
        assert!(debug.contains("integer"), "should contain data_type integer");
        assert!(debug.contains("42"), "should contain value 42");
    }
}
