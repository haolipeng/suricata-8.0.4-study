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

//! EVE JSON logger for IEC 60870-5-104 transactions.

use super::asdu::{
    Asdu, Cp16Time2a, Cp24Time2a, Cp56Time2a, InformationObject, InformationValue, Timestamp,
};
use super::iec104::Iec104Transaction;
use super::parser::ApciFrame;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_cp56time2a(ts: &Cp56Time2a, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("timestamp")?;
    js.set_uint("year", 2000 + ts.year as u64)?;
    js.set_uint("month", ts.month as u64)?;
    js.set_uint("day", ts.day as u64)?;
    js.set_uint("hour", ts.hour as u64)?;
    js.set_uint("minute", ts.minute as u64)?;
    js.set_uint("ms", ts.ms as u64)?;
    js.set_uint("dow", ts.dow as u64)?;
    js.set_bool("su", ts.su)?;
    js.set_bool("iv", ts.iv)?;
    js.close()?;
    Ok(())
}

fn log_cp24time2a(ts: &Cp24Time2a, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("timestamp")?;
    js.set_uint("minute", ts.minute as u64)?;
    js.set_uint("ms", ts.ms as u64)?;
    js.set_bool("iv", ts.iv)?;
    js.close()?;
    Ok(())
}

#[allow(dead_code)]
fn log_cp16time2a(ts: &Cp16Time2a, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("elapsed_time")?;
    js.set_uint("ms", ts.ms as u64)?;
    js.close()?;
    Ok(())
}

fn log_information_value(value: &InformationValue, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("value")?;
    match value {
        InformationValue::SinglePoint { spi, quality } => {
            js.set_bool("spi", *spi)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::DoublePoint { dpi, quality } => {
            js.set_uint("dpi", *dpi as u64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::StepPosition {
            value,
            transient,
            quality,
        } => {
            js.set_int("value", *value as i64)?;
            js.set_bool("transient", *transient)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::Bitstring32 { value, quality } => {
            js.set_string("bitstring", &format!("0x{:08X}", value))?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::Normalized { value, quality } => {
            js.set_int("normalized", *value as i64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::Scaled { value, quality } => {
            js.set_int("scaled", *value as i64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::ShortFloat { value, quality } => {
            js.set_float("float", *value as f64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::IntegratedTotal {
            counter,
            quality,
            seq_number,
        } => {
            js.set_int("counter", *counter as i64)?;
            js.set_uint("seq_number", *seq_number as u64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::SingleCommand { scs, qualifier } => {
            js.set_bool("scs", *scs)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::DoubleCommand { dcs, qualifier } => {
            js.set_uint("dcs", *dcs as u64)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::RegulatingStep { rcs, qualifier } => {
            js.set_uint("rcs", *rcs as u64)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::SetpointNormalized { value, qualifier } => {
            js.set_int("normalized", *value as i64)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::SetpointScaled { value, qualifier } => {
            js.set_int("scaled", *value as i64)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::SetpointFloat { value, qualifier } => {
            js.set_float("float", *value as f64)?;
            js.set_uint("qualifier", *qualifier as u64)?;
        }
        InformationValue::Interrogation { qualifier } => {
            js.set_uint("qoi", *qualifier as u64)?;
        }
        InformationValue::CounterInterrogation { qualifier } => {
            js.set_uint("qcc", *qualifier as u64)?;
        }
        InformationValue::ClockSync { ref time } => {
            js.set_uint("year", 2000 + time.year as u64)?;
            js.set_uint("month", time.month as u64)?;
            js.set_uint("day", time.day as u64)?;
            js.set_uint("hour", time.hour as u64)?;
            js.set_uint("minute", time.minute as u64)?;
            js.set_uint("ms", time.ms as u64)?;
        }
        InformationValue::TestCommand { fbp } => {
            js.set_uint("fbp", *fbp as u64)?;
        }
        InformationValue::ResetProcess { qualifier } => {
            js.set_uint("qrp", *qualifier as u64)?;
        }
        InformationValue::DelayAcquisition { ref time } => {
            js.set_uint("ms", time.ms as u64)?;
        }
        InformationValue::EndOfInit { coi } => {
            js.set_uint("coi", *coi as u64)?;
        }
        InformationValue::PackedSinglePoint { scd, quality } => {
            js.set_string("scd", &format!("0x{:08X}", scd))?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::ProtectionEvent {
            event,
            ref elapsed,
            quality,
        } => {
            js.set_uint("event", *event as u64)?;
            js.set_uint("elapsed_ms", elapsed.ms as u64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::PackedStartEvents {
            events,
            ref elapsed,
            quality,
        } => {
            js.set_string("events", &format!("0x{:02X}", events))?;
            js.set_uint("elapsed_ms", elapsed.ms as u64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::PackedOutputCircuit {
            oci,
            ref elapsed,
            quality,
        } => {
            js.set_string("oci", &format!("0x{:02X}", oci))?;
            js.set_uint("elapsed_ms", elapsed.ms as u64)?;
            js.set_string("quality", &format!("0x{:02X}", quality))?;
        }
        InformationValue::ParamNormalized { value, qualifier } => {
            js.set_int("normalized", *value as i64)?;
            js.set_uint("qpm", *qualifier as u64)?;
        }
        InformationValue::ParamScaled { value, qualifier } => {
            js.set_int("scaled", *value as i64)?;
            js.set_uint("qpm", *qualifier as u64)?;
        }
        InformationValue::ParamFloat { value, qualifier } => {
            js.set_float("float", *value as f64)?;
            js.set_uint("qpm", *qualifier as u64)?;
        }
        InformationValue::ParamActivation { qualifier } => {
            js.set_uint("qpa", *qualifier as u64)?;
        }
        InformationValue::BitstringCommand { value } => {
            js.set_string("bitstring", &format!("0x{:08X}", value))?;
        }
        InformationValue::Raw(data) => {
            if !data.is_empty() {
                let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                js.set_string("raw", &hex)?;
            }
        }
    }
    js.close()?;
    Ok(())
}

fn log_information_object(
    obj: &InformationObject, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.start_object()?;
    js.set_uint("ioa", obj.ioa as u64)?;
    log_information_value(&obj.value, js)?;
    if let Some(ref ts) = obj.timestamp {
        match ts {
            Timestamp::Cp56(t) => log_cp56time2a(t, js)?,
            Timestamp::Cp24(t) => log_cp24time2a(t, js)?,
        }
    }
    js.close()?;
    Ok(())
}

fn log_asdu(asdu: &Asdu, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("asdu")?;
    js.set_uint("type_id", asdu.type_id.to_u8() as u64)?;
    js.set_string("type_name", asdu.type_id.as_str())?;
    js.set_bool("sq", asdu.is_sequence)?;
    js.set_uint("num_objects", asdu.num_objects as u64)?;

    // COT
    js.open_object("cot")?;
    js.set_uint("cause", asdu.cot.cause as u64)?;
    js.set_string("cause_name", asdu.cot.cause_str())?;
    js.set_bool("negative", asdu.cot.negative)?;
    js.set_bool("test", asdu.cot.test)?;
    js.set_uint("originator", asdu.cot.originator as u64)?;
    js.close()?;

    js.set_uint("common_addr", asdu.common_addr as u64)?;

    // Objects
    if !asdu.objects.is_empty() {
        js.open_array("objects")?;
        for obj in &asdu.objects {
            log_information_object(obj, js)?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

fn log_iec104(tx: &Iec104Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("iec104")?;

    js.set_string("frame_type", tx.apci.frame_type_str())?;

    // APCI fields
    js.open_object("apci")?;
    match &tx.apci {
        ApciFrame::IFrame {
            send_seq, recv_seq, ..
        } => {
            js.set_uint("send_seq", *send_seq as u64)?;
            js.set_uint("recv_seq", *recv_seq as u64)?;
        }
        ApciFrame::SFrame { recv_seq } => {
            js.set_uint("recv_seq", *recv_seq as u64)?;
        }
        ApciFrame::UFrame { function } => {
            js.set_string("function", function.as_str())?;
        }
    }
    js.close()?;

    // ASDU (only for I-frames)
    if let Some(ref asdu) = tx.asdu {
        log_asdu(asdu, js)?;
    }

    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCIec104LoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_iec104(tx, js).is_ok()
}
