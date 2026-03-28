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

//! ASDU (Application Service Data Unit) parser for IEC 60870-5-104.
//!
//! ASDU structure (Chinese standard: IOA=3B, CommonAddr=2B, COT=2B):
//!   TypeID(1B) | SQ+NumObj(1B) | COT(2B) | CommonAddr(2B) | InformationObjects...

use nom7::number::streaming::{le_u8, le_u16, le_u24, le_i16, le_u32};
use nom7::bytes::streaming::take;
use nom7::IResult;

// ---- TypeId ----

/// IEC 104 Type Identification
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum TypeId {
    // Process information in monitoring direction
    M_SP_NA_1 = 1,   // Single-point information
    M_SP_TA_1 = 2,   // Single-point with time tag
    M_DP_NA_1 = 3,   // Double-point information
    M_DP_TA_1 = 4,   // Double-point with time tag
    M_ST_NA_1 = 5,   // Step position information
    M_ST_TA_1 = 6,   // Step position with time tag
    M_BO_NA_1 = 7,   // Bitstring of 32 bit
    M_BO_TA_1 = 8,   // Bitstring with time tag
    M_ME_NA_1 = 9,   // Measured value, normalized
    M_ME_TA_1 = 10,  // Measured value, normalized with time tag
    M_ME_NB_1 = 11,  // Measured value, scaled
    M_ME_TB_1 = 12,  // Measured value, scaled with time tag
    M_ME_NC_1 = 13,  // Measured value, short floating point
    M_ME_TC_1 = 14,  // Measured value, short float with time tag
    M_IT_NA_1 = 15,  // Integrated totals
    M_IT_TA_1 = 16,  // Integrated totals with time tag
    M_EP_TA_1 = 17,  // Event of protection equipment with time tag
    M_EP_TB_1 = 18,  // Packed start events with time tag
    M_EP_TC_1 = 19,  // Packed output circuit info with time tag
    M_PS_NA_1 = 20,  // Packed single-point with status change detection
    M_ME_ND_1 = 21,  // Measured value, normalized without quality

    // Process information in monitoring direction with CP56Time2a
    M_SP_TB_1 = 30,  // Single-point with CP56Time2a
    M_DP_TB_1 = 31,  // Double-point with CP56Time2a
    M_ST_TB_1 = 32,  // Step position with CP56Time2a
    M_BO_TB_1 = 33,  // Bitstring with CP56Time2a
    M_ME_TD_1 = 34,  // Measured value, normalized with CP56Time2a
    M_ME_TE_1 = 35,  // Measured value, scaled with CP56Time2a
    M_ME_TF_1 = 36,  // Measured value, short float with CP56Time2a
    M_IT_TB_1 = 37,  // Integrated totals with CP56Time2a
    M_EP_TD_1 = 38,  // Event of protection with CP56Time2a
    M_EP_TE_1 = 39,  // Packed start events with CP56Time2a
    M_EP_TF_1 = 40,  // Packed output circuit info with CP56Time2a

    // Process information in control direction
    C_SC_NA_1 = 45,  // Single command
    C_DC_NA_1 = 46,  // Double command
    C_RC_NA_1 = 47,  // Regulating step command
    C_SE_NA_1 = 48,  // Set-point, normalized
    C_SE_NB_1 = 49,  // Set-point, scaled
    C_SE_NC_1 = 50,  // Set-point, short floating point
    C_BO_NA_1 = 51,  // Bitstring of 32 bit command

    // Process information in control direction with CP56Time2a
    C_SC_TA_1 = 58,  // Single command with CP56Time2a
    C_DC_TA_1 = 59,  // Double command with CP56Time2a
    C_RC_TA_1 = 60,  // Regulating step command with CP56Time2a
    C_SE_TA_1 = 61,  // Set-point, normalized with CP56Time2a
    C_SE_TB_1 = 62,  // Set-point, scaled with CP56Time2a
    C_SE_TC_1 = 63,  // Set-point, short float with CP56Time2a
    C_BO_TA_1 = 64,  // Bitstring command with CP56Time2a

    // System information in monitor direction
    M_EI_NA_1 = 70,  // End of initialization

    // System information in control direction
    C_IC_NA_1 = 100, // Interrogation command
    C_CI_NA_1 = 101, // Counter interrogation command
    C_RD_NA_1 = 102, // Read command
    C_CS_NA_1 = 103, // Clock synchronization command
    C_TS_NA_1 = 104, // Test command
    C_RP_NA_1 = 105, // Reset process command
    C_CD_NA_1 = 106, // Delay acquisition command
    C_TS_TA_1 = 107, // Test command with CP56Time2a

    // Parameter in control direction
    P_ME_NA_1 = 110, // Parameter of measured value, normalized
    P_ME_NB_1 = 111, // Parameter of measured value, scaled
    P_ME_NC_1 = 112, // Parameter of measured value, short float
    P_AC_NA_1 = 113, // Parameter activation

    // File transfer
    F_FR_NA_1 = 120, // File ready
    F_SR_NA_1 = 121, // Section ready
    F_SC_NA_1 = 122, // Call directory, select file, call file, call section
    F_LS_NA_1 = 123, // Last section, last segment
    F_AF_NA_1 = 124, // ACK file, ACK section
    F_SG_NA_1 = 125, // Segment
    F_DR_TA_1 = 126, // Directory
    F_SC_NB_1 = 127, // QueryLog

    Unknown(u8),
}

impl TypeId {
    pub fn from_u8(v: u8) -> TypeId {
        match v {
            1 => TypeId::M_SP_NA_1,
            2 => TypeId::M_SP_TA_1,
            3 => TypeId::M_DP_NA_1,
            4 => TypeId::M_DP_TA_1,
            5 => TypeId::M_ST_NA_1,
            6 => TypeId::M_ST_TA_1,
            7 => TypeId::M_BO_NA_1,
            8 => TypeId::M_BO_TA_1,
            9 => TypeId::M_ME_NA_1,
            10 => TypeId::M_ME_TA_1,
            11 => TypeId::M_ME_NB_1,
            12 => TypeId::M_ME_TB_1,
            13 => TypeId::M_ME_NC_1,
            14 => TypeId::M_ME_TC_1,
            15 => TypeId::M_IT_NA_1,
            16 => TypeId::M_IT_TA_1,
            17 => TypeId::M_EP_TA_1,
            18 => TypeId::M_EP_TB_1,
            19 => TypeId::M_EP_TC_1,
            20 => TypeId::M_PS_NA_1,
            21 => TypeId::M_ME_ND_1,
            30 => TypeId::M_SP_TB_1,
            31 => TypeId::M_DP_TB_1,
            32 => TypeId::M_ST_TB_1,
            33 => TypeId::M_BO_TB_1,
            34 => TypeId::M_ME_TD_1,
            35 => TypeId::M_ME_TE_1,
            36 => TypeId::M_ME_TF_1,
            37 => TypeId::M_IT_TB_1,
            38 => TypeId::M_EP_TD_1,
            39 => TypeId::M_EP_TE_1,
            40 => TypeId::M_EP_TF_1,
            45 => TypeId::C_SC_NA_1,
            46 => TypeId::C_DC_NA_1,
            47 => TypeId::C_RC_NA_1,
            48 => TypeId::C_SE_NA_1,
            49 => TypeId::C_SE_NB_1,
            50 => TypeId::C_SE_NC_1,
            51 => TypeId::C_BO_NA_1,
            58 => TypeId::C_SC_TA_1,
            59 => TypeId::C_DC_TA_1,
            60 => TypeId::C_RC_TA_1,
            61 => TypeId::C_SE_TA_1,
            62 => TypeId::C_SE_TB_1,
            63 => TypeId::C_SE_TC_1,
            64 => TypeId::C_BO_TA_1,
            70 => TypeId::M_EI_NA_1,
            100 => TypeId::C_IC_NA_1,
            101 => TypeId::C_CI_NA_1,
            102 => TypeId::C_RD_NA_1,
            103 => TypeId::C_CS_NA_1,
            104 => TypeId::C_TS_NA_1,
            105 => TypeId::C_RP_NA_1,
            106 => TypeId::C_CD_NA_1,
            107 => TypeId::C_TS_TA_1,
            110 => TypeId::P_ME_NA_1,
            111 => TypeId::P_ME_NB_1,
            112 => TypeId::P_ME_NC_1,
            113 => TypeId::P_AC_NA_1,
            120 => TypeId::F_FR_NA_1,
            121 => TypeId::F_SR_NA_1,
            122 => TypeId::F_SC_NA_1,
            123 => TypeId::F_LS_NA_1,
            124 => TypeId::F_AF_NA_1,
            125 => TypeId::F_SG_NA_1,
            126 => TypeId::F_DR_TA_1,
            127 => TypeId::F_SC_NB_1,
            other => TypeId::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TypeId::M_SP_NA_1 => "M_SP_NA_1",
            TypeId::M_SP_TA_1 => "M_SP_TA_1",
            TypeId::M_DP_NA_1 => "M_DP_NA_1",
            TypeId::M_DP_TA_1 => "M_DP_TA_1",
            TypeId::M_ST_NA_1 => "M_ST_NA_1",
            TypeId::M_ST_TA_1 => "M_ST_TA_1",
            TypeId::M_BO_NA_1 => "M_BO_NA_1",
            TypeId::M_BO_TA_1 => "M_BO_TA_1",
            TypeId::M_ME_NA_1 => "M_ME_NA_1",
            TypeId::M_ME_TA_1 => "M_ME_TA_1",
            TypeId::M_ME_NB_1 => "M_ME_NB_1",
            TypeId::M_ME_TB_1 => "M_ME_TB_1",
            TypeId::M_ME_NC_1 => "M_ME_NC_1",
            TypeId::M_ME_TC_1 => "M_ME_TC_1",
            TypeId::M_IT_NA_1 => "M_IT_NA_1",
            TypeId::M_IT_TA_1 => "M_IT_TA_1",
            TypeId::M_EP_TA_1 => "M_EP_TA_1",
            TypeId::M_EP_TB_1 => "M_EP_TB_1",
            TypeId::M_EP_TC_1 => "M_EP_TC_1",
            TypeId::M_PS_NA_1 => "M_PS_NA_1",
            TypeId::M_ME_ND_1 => "M_ME_ND_1",
            TypeId::M_SP_TB_1 => "M_SP_TB_1",
            TypeId::M_DP_TB_1 => "M_DP_TB_1",
            TypeId::M_ST_TB_1 => "M_ST_TB_1",
            TypeId::M_BO_TB_1 => "M_BO_TB_1",
            TypeId::M_ME_TD_1 => "M_ME_TD_1",
            TypeId::M_ME_TE_1 => "M_ME_TE_1",
            TypeId::M_ME_TF_1 => "M_ME_TF_1",
            TypeId::M_IT_TB_1 => "M_IT_TB_1",
            TypeId::M_EP_TD_1 => "M_EP_TD_1",
            TypeId::M_EP_TE_1 => "M_EP_TE_1",
            TypeId::M_EP_TF_1 => "M_EP_TF_1",
            TypeId::C_SC_NA_1 => "C_SC_NA_1",
            TypeId::C_DC_NA_1 => "C_DC_NA_1",
            TypeId::C_RC_NA_1 => "C_RC_NA_1",
            TypeId::C_SE_NA_1 => "C_SE_NA_1",
            TypeId::C_SE_NB_1 => "C_SE_NB_1",
            TypeId::C_SE_NC_1 => "C_SE_NC_1",
            TypeId::C_BO_NA_1 => "C_BO_NA_1",
            TypeId::C_SC_TA_1 => "C_SC_TA_1",
            TypeId::C_DC_TA_1 => "C_DC_TA_1",
            TypeId::C_RC_TA_1 => "C_RC_TA_1",
            TypeId::C_SE_TA_1 => "C_SE_TA_1",
            TypeId::C_SE_TB_1 => "C_SE_TB_1",
            TypeId::C_SE_TC_1 => "C_SE_TC_1",
            TypeId::C_BO_TA_1 => "C_BO_TA_1",
            TypeId::M_EI_NA_1 => "M_EI_NA_1",
            TypeId::C_IC_NA_1 => "C_IC_NA_1",
            TypeId::C_CI_NA_1 => "C_CI_NA_1",
            TypeId::C_RD_NA_1 => "C_RD_NA_1",
            TypeId::C_CS_NA_1 => "C_CS_NA_1",
            TypeId::C_TS_NA_1 => "C_TS_NA_1",
            TypeId::C_RP_NA_1 => "C_RP_NA_1",
            TypeId::C_CD_NA_1 => "C_CD_NA_1",
            TypeId::C_TS_TA_1 => "C_TS_TA_1",
            TypeId::P_ME_NA_1 => "P_ME_NA_1",
            TypeId::P_ME_NB_1 => "P_ME_NB_1",
            TypeId::P_ME_NC_1 => "P_ME_NC_1",
            TypeId::P_AC_NA_1 => "P_AC_NA_1",
            TypeId::F_FR_NA_1 => "F_FR_NA_1",
            TypeId::F_SR_NA_1 => "F_SR_NA_1",
            TypeId::F_SC_NA_1 => "F_SC_NA_1",
            TypeId::F_LS_NA_1 => "F_LS_NA_1",
            TypeId::F_AF_NA_1 => "F_AF_NA_1",
            TypeId::F_SG_NA_1 => "F_SG_NA_1",
            TypeId::F_DR_TA_1 => "F_DR_TA_1",
            TypeId::F_SC_NB_1 => "F_SC_NB_1",
            TypeId::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            TypeId::Unknown(v) => *v,
            other => {
                // Use as_str to get the right value - but simpler to just match
                // We have the repr(u8) but can't directly cast enums with data variants
                match other {
                    TypeId::M_SP_NA_1 => 1,
                    TypeId::M_SP_TA_1 => 2,
                    TypeId::M_DP_NA_1 => 3,
                    TypeId::M_DP_TA_1 => 4,
                    TypeId::M_ST_NA_1 => 5,
                    TypeId::M_ST_TA_1 => 6,
                    TypeId::M_BO_NA_1 => 7,
                    TypeId::M_BO_TA_1 => 8,
                    TypeId::M_ME_NA_1 => 9,
                    TypeId::M_ME_TA_1 => 10,
                    TypeId::M_ME_NB_1 => 11,
                    TypeId::M_ME_TB_1 => 12,
                    TypeId::M_ME_NC_1 => 13,
                    TypeId::M_ME_TC_1 => 14,
                    TypeId::M_IT_NA_1 => 15,
                    TypeId::M_IT_TA_1 => 16,
                    TypeId::M_EP_TA_1 => 17,
                    TypeId::M_EP_TB_1 => 18,
                    TypeId::M_EP_TC_1 => 19,
                    TypeId::M_PS_NA_1 => 20,
                    TypeId::M_ME_ND_1 => 21,
                    TypeId::M_SP_TB_1 => 30,
                    TypeId::M_DP_TB_1 => 31,
                    TypeId::M_ST_TB_1 => 32,
                    TypeId::M_BO_TB_1 => 33,
                    TypeId::M_ME_TD_1 => 34,
                    TypeId::M_ME_TE_1 => 35,
                    TypeId::M_ME_TF_1 => 36,
                    TypeId::M_IT_TB_1 => 37,
                    TypeId::M_EP_TD_1 => 38,
                    TypeId::M_EP_TE_1 => 39,
                    TypeId::M_EP_TF_1 => 40,
                    TypeId::C_SC_NA_1 => 45,
                    TypeId::C_DC_NA_1 => 46,
                    TypeId::C_RC_NA_1 => 47,
                    TypeId::C_SE_NA_1 => 48,
                    TypeId::C_SE_NB_1 => 49,
                    TypeId::C_SE_NC_1 => 50,
                    TypeId::C_BO_NA_1 => 51,
                    TypeId::C_SC_TA_1 => 58,
                    TypeId::C_DC_TA_1 => 59,
                    TypeId::C_RC_TA_1 => 60,
                    TypeId::C_SE_TA_1 => 61,
                    TypeId::C_SE_TB_1 => 62,
                    TypeId::C_SE_TC_1 => 63,
                    TypeId::C_BO_TA_1 => 64,
                    TypeId::M_EI_NA_1 => 70,
                    TypeId::C_IC_NA_1 => 100,
                    TypeId::C_CI_NA_1 => 101,
                    TypeId::C_RD_NA_1 => 102,
                    TypeId::C_CS_NA_1 => 103,
                    TypeId::C_TS_NA_1 => 104,
                    TypeId::C_RP_NA_1 => 105,
                    TypeId::C_CD_NA_1 => 106,
                    TypeId::C_TS_TA_1 => 107,
                    TypeId::P_ME_NA_1 => 110,
                    TypeId::P_ME_NB_1 => 111,
                    TypeId::P_ME_NC_1 => 112,
                    TypeId::P_AC_NA_1 => 113,
                    TypeId::F_FR_NA_1 => 120,
                    TypeId::F_SR_NA_1 => 121,
                    TypeId::F_SC_NA_1 => 122,
                    TypeId::F_LS_NA_1 => 123,
                    TypeId::F_AF_NA_1 => 124,
                    TypeId::F_SG_NA_1 => 125,
                    TypeId::F_DR_TA_1 => 126,
                    TypeId::F_SC_NB_1 => 127,
                    TypeId::Unknown(v) => *v,
                }
            }
        }
    }

    /// Returns true if this TypeId is in a known valid range
    pub fn is_valid(&self) -> bool {
        !matches!(self, TypeId::Unknown(_))
    }
}

// ---- Cause of Transmission ----

/// Cause of Transmission
#[derive(Debug, PartialEq, Clone)]
pub struct CauseOfTransmission {
    /// Cause value (6 bits, 0-63)
    pub cause: u8,
    /// Positive/Negative confirm flag
    pub negative: bool,
    /// Test flag
    pub test: bool,
    /// Originator address (0 = not used)
    pub originator: u8,
}

impl CauseOfTransmission {
    pub fn cause_str(&self) -> &'static str {
        match self.cause {
            0 => "not_used",
            1 => "periodic",
            2 => "background",
            3 => "spontaneous",
            4 => "initialized",
            5 => "request",
            6 => "activation",
            7 => "activation_con",
            8 => "deactivation",
            9 => "deactivation_con",
            10 => "activation_termination",
            11 => "return_remote",
            12 => "return_local",
            13 => "file_transfer",
            14..=19 => "reserved",
            20 => "interrogated_station",
            21 => "interrogated_group_1",
            22 => "interrogated_group_2",
            23 => "interrogated_group_3",
            24 => "interrogated_group_4",
            25 => "interrogated_group_5",
            26 => "interrogated_group_6",
            27 => "interrogated_group_7",
            28 => "interrogated_group_8",
            29 => "interrogated_group_9",
            30 => "interrogated_group_10",
            31 => "interrogated_group_11",
            32 => "interrogated_group_12",
            33 => "interrogated_group_13",
            34 => "interrogated_group_14",
            35 => "interrogated_group_15",
            36 => "interrogated_group_16",
            37 => "counter_request",
            38 => "counter_group_1",
            39 => "counter_group_2",
            40 => "counter_group_3",
            41 => "counter_group_4",
            44 => "unknown_type_id",
            45 => "unknown_cot",
            46 => "unknown_common_addr",
            47 => "unknown_ioa",
            _ => "unknown",
        }
    }

    /// Returns true if the cause value is in valid range
    pub fn is_valid(&self) -> bool {
        self.cause <= 47
    }
}

// ---- CP56Time2a timestamp ----

/// CP56Time2a - 7 bytes timestamp
#[derive(Debug, PartialEq, Clone)]
pub struct Cp56Time2a {
    pub ms: u16,       // milliseconds (0-59999)
    pub minute: u8,    // (0-59)
    pub iv: bool,      // invalid flag
    pub hour: u8,      // (0-23)
    pub su: bool,      // summer time
    pub day: u8,       // day of month (1-31)
    pub dow: u8,       // day of week (1-7, 1=Monday)
    pub month: u8,     // (1-12)
    pub year: u8,      // (0-99, year 2000+)
}

/// CP24Time2a - 3 bytes timestamp (ms + minute)
#[derive(Debug, PartialEq, Clone)]
pub struct Cp24Time2a {
    pub ms: u16,
    pub minute: u8,
    pub iv: bool,
}

// ---- Information Object Value ----

/// Value types for information objects
#[derive(Debug, PartialEq, Clone)]
pub enum InformationValue {
    /// Single-point information (SPI + quality)
    SinglePoint { spi: bool, quality: u8 },
    /// Double-point information (DPI + quality)
    DoublePoint { dpi: u8, quality: u8 },
    /// Step position (value + transient + quality)
    StepPosition { value: i8, transient: bool, quality: u8 },
    /// Bitstring of 32 bit + quality
    Bitstring32 { value: u32, quality: u8 },
    /// Normalized value (-1.0 to ~1.0) + quality
    Normalized { value: i16, quality: u8 },
    /// Scaled value + quality
    Scaled { value: i16, quality: u8 },
    /// Short floating point + quality
    ShortFloat { value: f32, quality: u8 },
    /// Integrated total (counter + quality)
    IntegratedTotal { counter: i32, quality: u8, seq_number: u8 },
    /// Single command (SCS + qualifier)
    SingleCommand { scs: bool, qualifier: u8 },
    /// Double command (DCS + qualifier)
    DoubleCommand { dcs: u8, qualifier: u8 },
    /// Regulating step command (RCS + qualifier)
    RegulatingStep { rcs: u8, qualifier: u8 },
    /// Set-point normalized + qualifier
    SetpointNormalized { value: i16, qualifier: u8 },
    /// Set-point scaled + qualifier
    SetpointScaled { value: i16, qualifier: u8 },
    /// Set-point short float + qualifier
    SetpointFloat { value: f32, qualifier: u8 },
    /// Interrogation command qualifier
    Interrogation { qualifier: u8 },
    /// Counter interrogation qualifier
    CounterInterrogation { qualifier: u8 },
    /// Clock synchronization time
    ClockSync { time: Cp56Time2a },
    /// Test command
    TestCommand { fbp: u16 },
    /// Reset process qualifier
    ResetProcess { qualifier: u8 },
    /// Delay acquisition time
    DelayAcquisition { time: Cp16Time2a },
    /// End of initialization cause
    EndOfInit { coi: u8 },
    /// Packed single-point with status change detection
    PackedSinglePoint { scd: u32, quality: u8 },
    /// Protection event (single event + elapsed time + quality)
    ProtectionEvent { event: u8, elapsed: Cp16Time2a, quality: u8 },
    /// Packed start events of protection (events + elapsed + quality)
    PackedStartEvents { events: u8, elapsed: Cp16Time2a, quality: u8 },
    /// Packed output circuit info (oci + elapsed + quality)
    PackedOutputCircuit { oci: u8, elapsed: Cp16Time2a, quality: u8 },
    /// Parameter normalized
    ParamNormalized { value: i16, qualifier: u8 },
    /// Parameter scaled
    ParamScaled { value: i16, qualifier: u8 },
    /// Parameter short float
    ParamFloat { value: f32, qualifier: u8 },
    /// Parameter activation
    ParamActivation { qualifier: u8 },
    /// Bitstring command
    BitstringCommand { value: u32 },
    /// Raw/unparsed data for unsupported types
    Raw(Vec<u8>),
}

/// CP16Time2a - 2 bytes (milliseconds only)
#[derive(Debug, PartialEq, Clone)]
pub struct Cp16Time2a {
    pub ms: u16,
}

// ---- Information Object ----

/// Parsed information object
#[derive(Debug, PartialEq, Clone)]
pub struct InformationObject {
    pub ioa: u32,
    pub value: InformationValue,
    pub timestamp: Option<Timestamp>,
}

/// Timestamp can be either CP24Time2a or CP56Time2a
#[derive(Debug, PartialEq, Clone)]
pub enum Timestamp {
    Cp24(Cp24Time2a),
    Cp56(Cp56Time2a),
}

// ---- ASDU ----

/// Parsed ASDU
#[derive(Debug, PartialEq, Clone)]
pub struct Asdu {
    pub type_id: TypeId,
    pub is_sequence: bool,
    pub num_objects: u8,
    pub cot: CauseOfTransmission,
    pub common_addr: u16,
    pub objects: Vec<InformationObject>,
}

// ---- Parsing functions ----

/// Parse ASDU header (6 bytes for Chinese standard)
pub fn parse_asdu_header(i: &[u8]) -> IResult<&[u8], (TypeId, bool, u8, CauseOfTransmission, u16)> {
    let (i, type_id_raw) = le_u8(i)?;
    let (i, sq_num) = le_u8(i)?;
    let is_sequence = (sq_num & 0x80) != 0;
    let num_objects = sq_num & 0x7F;

    // COT: 2 bytes (Chinese standard includes originator address)
    let (i, cot_byte1) = le_u8(i)?;
    let (i, originator) = le_u8(i)?;
    let cause = cot_byte1 & 0x3F;
    let negative = (cot_byte1 & 0x40) != 0;
    let test = (cot_byte1 & 0x80) != 0;

    // Common address: 2 bytes
    let (i, common_addr) = le_u16(i)?;

    let type_id = TypeId::from_u8(type_id_raw);
    let cot = CauseOfTransmission {
        cause,
        negative,
        test,
        originator,
    };

    Ok((i, (type_id, is_sequence, num_objects, cot, common_addr)))
}

/// Parse CP56Time2a (7 bytes)
pub fn parse_cp56time2a(i: &[u8]) -> IResult<&[u8], Cp56Time2a> {
    let (i, ms) = le_u16(i)?;
    let (i, min_byte) = le_u8(i)?;
    let (i, hour_byte) = le_u8(i)?;
    let (i, day_byte) = le_u8(i)?;
    let (i, month_byte) = le_u8(i)?;
    let (i, year_byte) = le_u8(i)?;

    Ok((
        i,
        Cp56Time2a {
            ms,
            minute: min_byte & 0x3F,
            iv: (min_byte & 0x80) != 0,
            hour: hour_byte & 0x1F,
            su: (hour_byte & 0x80) != 0,
            day: day_byte & 0x1F,
            dow: (day_byte >> 5) & 0x07,
            month: month_byte & 0x0F,
            year: year_byte & 0x7F,
        },
    ))
}

/// Parse CP24Time2a (3 bytes)
pub fn parse_cp24time2a(i: &[u8]) -> IResult<&[u8], Cp24Time2a> {
    let (i, ms) = le_u16(i)?;
    let (i, min_byte) = le_u8(i)?;

    Ok((
        i,
        Cp24Time2a {
            ms,
            minute: min_byte & 0x3F,
            iv: (min_byte & 0x80) != 0,
        },
    ))
}

/// Parse CP16Time2a (2 bytes - elapsed time in ms)
pub fn parse_cp16time2a(i: &[u8]) -> IResult<&[u8], Cp16Time2a> {
    let (i, ms) = le_u16(i)?;
    Ok((i, Cp16Time2a { ms }))
}

/// Parse IOA (3 bytes, little-endian)
fn parse_ioa(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, v) = le_u24(i)?;
    Ok((i, v))
}

/// Parse single-point information element (1 byte)
fn parse_siq(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, b) = le_u8(i)?;
    Ok((
        i,
        InformationValue::SinglePoint {
            spi: (b & 0x01) != 0,
            quality: b & 0xF0,
        },
    ))
}

/// Parse double-point information element (1 byte)
fn parse_diq(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, b) = le_u8(i)?;
    Ok((
        i,
        InformationValue::DoublePoint {
            dpi: b & 0x03,
            quality: b & 0xF0,
        },
    ))
}

/// Parse step position (2 bytes: value+transient, quality)
fn parse_vti_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, vti) = le_u8(i)?;
    let (i, qds) = le_u8(i)?;
    let value = ((vti & 0x7F) as i8) | if vti & 0x40 != 0 { -128i8 } else { 0 };
    Ok((
        i,
        InformationValue::StepPosition {
            value,
            transient: (vti & 0x80) != 0,
            quality: qds,
        },
    ))
}

/// Parse bitstring (5 bytes: 4 bytes BSI + 1 byte QDS)
fn parse_bsi_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_u32(i)?;
    let (i, qds) = le_u8(i)?;
    Ok((
        i,
        InformationValue::Bitstring32 {
            value,
            quality: qds,
        },
    ))
}

/// Parse normalized value (3 bytes: 2 bytes NVA + 1 byte QDS)
fn parse_nva_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_i16(i)?;
    let (i, qds) = le_u8(i)?;
    Ok((
        i,
        InformationValue::Normalized {
            value,
            quality: qds,
        },
    ))
}

/// Parse normalized value without quality (2 bytes: NVA only)
fn parse_nva_only(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_i16(i)?;
    Ok((
        i,
        InformationValue::Normalized {
            value,
            quality: 0,
        },
    ))
}

/// Parse scaled value (3 bytes: 2 bytes SVA + 1 byte QDS)
fn parse_sva_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_i16(i)?;
    let (i, qds) = le_u8(i)?;
    Ok((
        i,
        InformationValue::Scaled {
            value,
            quality: qds,
        },
    ))
}

/// Parse short floating point (5 bytes: 4 bytes IEEE 754 + 1 byte QDS)
fn parse_float_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, raw) = le_u32(i)?;
    let value = f32::from_bits(raw);
    let (i, qds) = le_u8(i)?;
    Ok((
        i,
        InformationValue::ShortFloat {
            value,
            quality: qds,
        },
    ))
}

/// Parse integrated total (5 bytes: 4 bytes BCR counter + 1 byte quality)
fn parse_bcr(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, counter_raw) = le_u32(i)?;
    let counter = counter_raw as i32;
    let (i, quality_byte) = le_u8(i)?;
    let seq_number = quality_byte & 0x1F;
    let quality = quality_byte & 0xE0;
    Ok((
        i,
        InformationValue::IntegratedTotal {
            counter,
            quality,
            seq_number,
        },
    ))
}

/// Parse single command (1 byte: SCO)
fn parse_sco(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, sco) = le_u8(i)?;
    Ok((
        i,
        InformationValue::SingleCommand {
            scs: (sco & 0x01) != 0,
            qualifier: (sco >> 2) & 0x1F,
        },
    ))
}

/// Parse double command (1 byte: DCO)
fn parse_dco(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, dco) = le_u8(i)?;
    Ok((
        i,
        InformationValue::DoubleCommand {
            dcs: dco & 0x03,
            qualifier: (dco >> 2) & 0x1F,
        },
    ))
}

/// Parse regulating step command (1 byte: RCO)
fn parse_rco(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, rco) = le_u8(i)?;
    Ok((
        i,
        InformationValue::RegulatingStep {
            rcs: rco & 0x03,
            qualifier: (rco >> 2) & 0x1F,
        },
    ))
}

/// Parse set-point normalized command (3 bytes: NVA + QOS)
fn parse_nva_qos(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_i16(i)?;
    let (i, qos) = le_u8(i)?;
    Ok((
        i,
        InformationValue::SetpointNormalized {
            value,
            qualifier: qos,
        },
    ))
}

/// Parse set-point scaled command (3 bytes: SVA + QOS)
fn parse_sva_qos(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, value) = le_i16(i)?;
    let (i, qos) = le_u8(i)?;
    Ok((
        i,
        InformationValue::SetpointScaled {
            value,
            qualifier: qos,
        },
    ))
}

/// Parse set-point short float command (5 bytes: float + QOS)
fn parse_float_qos(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, raw) = le_u32(i)?;
    let value = f32::from_bits(raw);
    let (i, qos) = le_u8(i)?;
    Ok((
        i,
        InformationValue::SetpointFloat {
            value,
            qualifier: qos,
        },
    ))
}

/// Parse protection event (3 bytes: event + CP16Time2a)
fn parse_sep_cp16(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, event) = le_u8(i)?;
    let (i, elapsed) = parse_cp16time2a(i)?;
    let quality = event & 0xF0;
    Ok((
        i,
        InformationValue::ProtectionEvent {
            event: event & 0x03,
            elapsed,
            quality,
        },
    ))
}

/// Parse packed start events (3 bytes: SPE + CP16Time2a + QDP)
fn parse_spe_cp16_qdp(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, events) = le_u8(i)?;
    let (i, elapsed) = parse_cp16time2a(i)?;
    let (i, quality) = le_u8(i)?;
    Ok((
        i,
        InformationValue::PackedStartEvents {
            events,
            elapsed,
            quality,
        },
    ))
}

/// Parse packed output circuit info (3 bytes: OCI + CP16Time2a + QDP)
fn parse_oci_cp16_qdp(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, oci) = le_u8(i)?;
    let (i, elapsed) = parse_cp16time2a(i)?;
    let (i, quality) = le_u8(i)?;
    Ok((
        i,
        InformationValue::PackedOutputCircuit {
            oci,
            elapsed,
            quality,
        },
    ))
}

/// Parse packed single-point with SCD (5 bytes: SCD(4) + QDS(1))
fn parse_scd_qds(i: &[u8]) -> IResult<&[u8], InformationValue> {
    let (i, scd) = le_u32(i)?;
    let (i, quality) = le_u8(i)?;
    Ok((
        i,
        InformationValue::PackedSinglePoint { scd, quality },
    ))
}

/// Determine the size of one information element (excluding IOA) for a given TypeId.
/// Returns None for types that cannot be parsed or have variable length.
fn element_size(type_id: &TypeId) -> Option<usize> {
    match type_id {
        // Monitoring: single-point
        TypeId::M_SP_NA_1 => Some(1),           // SIQ
        TypeId::M_SP_TA_1 => Some(1 + 3),       // SIQ + CP24
        TypeId::M_SP_TB_1 => Some(1 + 7),       // SIQ + CP56
        // Monitoring: double-point
        TypeId::M_DP_NA_1 => Some(1),
        TypeId::M_DP_TA_1 => Some(1 + 3),
        TypeId::M_DP_TB_1 => Some(1 + 7),
        // Step position
        TypeId::M_ST_NA_1 => Some(2),           // VTI + QDS
        TypeId::M_ST_TA_1 => Some(2 + 3),
        TypeId::M_ST_TB_1 => Some(2 + 7),
        // Bitstring
        TypeId::M_BO_NA_1 => Some(5),           // BSI(4) + QDS(1)
        TypeId::M_BO_TA_1 => Some(5 + 3),
        TypeId::M_BO_TB_1 => Some(5 + 7),
        // Normalized
        TypeId::M_ME_NA_1 => Some(3),           // NVA(2) + QDS(1)
        TypeId::M_ME_TA_1 => Some(3 + 3),
        TypeId::M_ME_TD_1 => Some(3 + 7),
        TypeId::M_ME_ND_1 => Some(2),           // NVA(2) only
        // Scaled
        TypeId::M_ME_NB_1 => Some(3),           // SVA(2) + QDS(1)
        TypeId::M_ME_TB_1 => Some(3 + 3),
        TypeId::M_ME_TE_1 => Some(3 + 7),
        // Short float
        TypeId::M_ME_NC_1 => Some(5),           // float(4) + QDS(1)
        TypeId::M_ME_TC_1 => Some(5 + 3),
        TypeId::M_ME_TF_1 => Some(5 + 7),
        // Integrated totals
        TypeId::M_IT_NA_1 => Some(5),           // BCR
        TypeId::M_IT_TA_1 => Some(5 + 3),
        TypeId::M_IT_TB_1 => Some(5 + 7),
        // Protection events
        TypeId::M_EP_TA_1 => Some(3 + 3),       // SEP + CP16 + CP24
        TypeId::M_EP_TB_1 => Some(4 + 3),       // SPE + QDP + CP16 + CP24
        TypeId::M_EP_TC_1 => Some(4 + 3),       // OCI + QDP + CP16 + CP24
        TypeId::M_EP_TD_1 => Some(3 + 7),
        TypeId::M_EP_TE_1 => Some(4 + 7),
        TypeId::M_EP_TF_1 => Some(4 + 7),
        // Packed single point
        TypeId::M_PS_NA_1 => Some(5),           // SCD(4) + QDS(1)
        // Commands
        TypeId::C_SC_NA_1 => Some(1),
        TypeId::C_DC_NA_1 => Some(1),
        TypeId::C_RC_NA_1 => Some(1),
        TypeId::C_SE_NA_1 => Some(3),           // NVA + QOS
        TypeId::C_SE_NB_1 => Some(3),           // SVA + QOS
        TypeId::C_SE_NC_1 => Some(5),           // float + QOS
        TypeId::C_BO_NA_1 => Some(4),           // BSI
        // Commands with CP56
        TypeId::C_SC_TA_1 => Some(1 + 7),
        TypeId::C_DC_TA_1 => Some(1 + 7),
        TypeId::C_RC_TA_1 => Some(1 + 7),
        TypeId::C_SE_TA_1 => Some(3 + 7),
        TypeId::C_SE_TB_1 => Some(3 + 7),
        TypeId::C_SE_TC_1 => Some(5 + 7),
        TypeId::C_BO_TA_1 => Some(4 + 7),
        // System commands
        TypeId::M_EI_NA_1 => Some(1),           // COI
        TypeId::C_IC_NA_1 => Some(1),           // QOI
        TypeId::C_CI_NA_1 => Some(1),           // QCC
        TypeId::C_RD_NA_1 => Some(0),           // no IE
        TypeId::C_CS_NA_1 => Some(7),           // CP56Time2a
        TypeId::C_TS_NA_1 => Some(2),           // FBP
        TypeId::C_RP_NA_1 => Some(1),           // QRP
        TypeId::C_CD_NA_1 => Some(2),           // CP16Time2a
        TypeId::C_TS_TA_1 => Some(2 + 7),       // FBP + CP56
        // Parameters
        TypeId::P_ME_NA_1 => Some(3),           // NVA + QPM
        TypeId::P_ME_NB_1 => Some(3),           // SVA + QPM
        TypeId::P_ME_NC_1 => Some(5),           // float + QPM
        TypeId::P_AC_NA_1 => Some(1),           // QPA
        _ => None,
    }
}

/// Parse a single information element value (excluding IOA and timestamp)
fn parse_information_element<'a>(i: &'a [u8], type_id: &TypeId) -> IResult<&'a [u8], InformationValue> {
    match type_id {
        // Single-point
        TypeId::M_SP_NA_1 | TypeId::M_SP_TA_1 | TypeId::M_SP_TB_1 => parse_siq(i),
        // Double-point
        TypeId::M_DP_NA_1 | TypeId::M_DP_TA_1 | TypeId::M_DP_TB_1 => parse_diq(i),
        // Step position
        TypeId::M_ST_NA_1 | TypeId::M_ST_TA_1 | TypeId::M_ST_TB_1 => parse_vti_qds(i),
        // Bitstring
        TypeId::M_BO_NA_1 | TypeId::M_BO_TA_1 | TypeId::M_BO_TB_1 => parse_bsi_qds(i),
        // Normalized
        TypeId::M_ME_NA_1 | TypeId::M_ME_TA_1 | TypeId::M_ME_TD_1 => parse_nva_qds(i),
        TypeId::M_ME_ND_1 => parse_nva_only(i),
        // Scaled
        TypeId::M_ME_NB_1 | TypeId::M_ME_TB_1 | TypeId::M_ME_TE_1 => parse_sva_qds(i),
        // Short float
        TypeId::M_ME_NC_1 | TypeId::M_ME_TC_1 | TypeId::M_ME_TF_1 => parse_float_qds(i),
        // Integrated totals
        TypeId::M_IT_NA_1 | TypeId::M_IT_TA_1 | TypeId::M_IT_TB_1 => parse_bcr(i),
        // Protection events
        TypeId::M_EP_TA_1 | TypeId::M_EP_TD_1 => parse_sep_cp16(i),
        TypeId::M_EP_TB_1 | TypeId::M_EP_TE_1 => parse_spe_cp16_qdp(i),
        TypeId::M_EP_TC_1 | TypeId::M_EP_TF_1 => parse_oci_cp16_qdp(i),
        // Packed single-point
        TypeId::M_PS_NA_1 => parse_scd_qds(i),
        // Commands
        TypeId::C_SC_NA_1 | TypeId::C_SC_TA_1 => parse_sco(i),
        TypeId::C_DC_NA_1 | TypeId::C_DC_TA_1 => parse_dco(i),
        TypeId::C_RC_NA_1 | TypeId::C_RC_TA_1 => parse_rco(i),
        TypeId::C_SE_NA_1 | TypeId::C_SE_TA_1 => parse_nva_qos(i),
        TypeId::C_SE_NB_1 | TypeId::C_SE_TB_1 => parse_sva_qos(i),
        TypeId::C_SE_NC_1 | TypeId::C_SE_TC_1 => parse_float_qos(i),
        TypeId::C_BO_NA_1 | TypeId::C_BO_TA_1 => {
            let (i, value) = le_u32(i)?;
            Ok((i, InformationValue::BitstringCommand { value }))
        }
        // System commands
        TypeId::M_EI_NA_1 => {
            let (i, coi) = le_u8(i)?;
            Ok((i, InformationValue::EndOfInit { coi }))
        }
        TypeId::C_IC_NA_1 => {
            let (i, qoi) = le_u8(i)?;
            Ok((i, InformationValue::Interrogation { qualifier: qoi }))
        }
        TypeId::C_CI_NA_1 => {
            let (i, qcc) = le_u8(i)?;
            Ok((i, InformationValue::CounterInterrogation { qualifier: qcc }))
        }
        TypeId::C_RD_NA_1 => {
            // Read command has no information element
            Ok((i, InformationValue::Raw(Vec::new())))
        }
        TypeId::C_CS_NA_1 => {
            let (i, time) = parse_cp56time2a(i)?;
            Ok((i, InformationValue::ClockSync { time }))
        }
        TypeId::C_TS_NA_1 | TypeId::C_TS_TA_1 => {
            let (i, fbp) = le_u16(i)?;
            Ok((i, InformationValue::TestCommand { fbp }))
        }
        TypeId::C_RP_NA_1 => {
            let (i, qrp) = le_u8(i)?;
            Ok((i, InformationValue::ResetProcess { qualifier: qrp }))
        }
        TypeId::C_CD_NA_1 => {
            let (i, time) = parse_cp16time2a(i)?;
            Ok((i, InformationValue::DelayAcquisition { time }))
        }
        // Parameters
        TypeId::P_ME_NA_1 => {
            let (i, value) = le_i16(i)?;
            let (i, qpm) = le_u8(i)?;
            Ok((i, InformationValue::ParamNormalized { value, qualifier: qpm }))
        }
        TypeId::P_ME_NB_1 => {
            let (i, value) = le_i16(i)?;
            let (i, qpm) = le_u8(i)?;
            Ok((i, InformationValue::ParamScaled { value, qualifier: qpm }))
        }
        TypeId::P_ME_NC_1 => {
            let (i, raw) = le_u32(i)?;
            let value = f32::from_bits(raw);
            let (i, qpm) = le_u8(i)?;
            Ok((i, InformationValue::ParamFloat { value, qualifier: qpm }))
        }
        TypeId::P_AC_NA_1 => {
            let (i, qpa) = le_u8(i)?;
            Ok((i, InformationValue::ParamActivation { qualifier: qpa }))
        }
        // Unknown or file transfer types - take remaining as raw
        _ => {
            if let Some(size) = element_size(type_id) {
                let (i, data) = take(size)(i)?;
                Ok((i, InformationValue::Raw(data.to_vec())))
            } else {
                // Cannot determine size, take all remaining
                Ok((&i[i.len()..], InformationValue::Raw(i.to_vec())))
            }
        }
    }
}

/// Determine if a TypeId has a CP24Time2a timestamp
fn has_cp24_time(type_id: &TypeId) -> bool {
    matches!(
        type_id,
        TypeId::M_SP_TA_1
            | TypeId::M_DP_TA_1
            | TypeId::M_ST_TA_1
            | TypeId::M_BO_TA_1
            | TypeId::M_ME_TA_1
            | TypeId::M_ME_TB_1
            | TypeId::M_ME_TC_1
            | TypeId::M_IT_TA_1
            | TypeId::M_EP_TA_1
            | TypeId::M_EP_TB_1
            | TypeId::M_EP_TC_1
    )
}

/// Determine if a TypeId has a CP56Time2a timestamp
fn has_cp56_time(type_id: &TypeId) -> bool {
    matches!(
        type_id,
        TypeId::M_SP_TB_1
            | TypeId::M_DP_TB_1
            | TypeId::M_ST_TB_1
            | TypeId::M_BO_TB_1
            | TypeId::M_ME_TD_1
            | TypeId::M_ME_TE_1
            | TypeId::M_ME_TF_1
            | TypeId::M_IT_TB_1
            | TypeId::M_EP_TD_1
            | TypeId::M_EP_TE_1
            | TypeId::M_EP_TF_1
            | TypeId::C_SC_TA_1
            | TypeId::C_DC_TA_1
            | TypeId::C_RC_TA_1
            | TypeId::C_SE_TA_1
            | TypeId::C_SE_TB_1
            | TypeId::C_SE_TC_1
            | TypeId::C_BO_TA_1
            | TypeId::C_TS_TA_1
    )
}

/// Parse optional timestamp after information element
fn parse_timestamp<'a>(i: &'a [u8], type_id: &TypeId) -> IResult<&'a [u8], Option<Timestamp>> {
    if has_cp56_time(type_id) {
        let (i, ts) = parse_cp56time2a(i)?;
        Ok((i, Some(Timestamp::Cp56(ts))))
    } else if has_cp24_time(type_id) {
        let (i, ts) = parse_cp24time2a(i)?;
        Ok((i, Some(Timestamp::Cp24(ts))))
    } else {
        Ok((i, None))
    }
}

/// Parse all information objects from ASDU data.
/// Handles both SQ=0 (each object has its own IOA) and SQ=1 (sequential IOA).
pub fn parse_information_objects<'a>(
    i: &'a [u8],
    type_id: &TypeId,
    is_sequence: bool,
    num_objects: u8,
) -> IResult<&'a [u8], Vec<InformationObject>> {
    let mut objects = Vec::with_capacity(num_objects as usize);
    let mut input = i;

    if is_sequence && num_objects > 0 {
        // SQ=1: First IOA, then consecutive information elements
        let (rem, base_ioa) = parse_ioa(input)?;
        input = rem;
        for idx in 0..num_objects {
            let (rem, value) = parse_information_element(input, type_id)?;
            let (rem, timestamp) = parse_timestamp(rem, type_id)?;
            input = rem;
            objects.push(InformationObject {
                ioa: base_ioa + idx as u32,
                value,
                timestamp,
            });
        }
    } else {
        // SQ=0: Each object has its own IOA
        for _ in 0..num_objects {
            let (rem, ioa) = parse_ioa(input)?;
            let (rem, value) = parse_information_element(rem, type_id)?;
            let (rem, timestamp) = parse_timestamp(rem, type_id)?;
            input = rem;
            objects.push(InformationObject {
                ioa,
                value,
                timestamp,
            });
        }
    }

    Ok((input, objects))
}

/// Parse a complete ASDU from raw bytes
pub fn parse_asdu(i: &[u8]) -> IResult<&[u8], Asdu> {
    let (i, (type_id, is_sequence, num_objects, cot, common_addr)) = parse_asdu_header(i)?;
    let (i, objects) = parse_information_objects(i, &type_id, is_sequence, num_objects)?;

    Ok((
        i,
        Asdu {
            type_id,
            is_sequence,
            num_objects,
            cot,
            common_addr,
            objects,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_id_from_u8() {
        assert_eq!(TypeId::from_u8(1), TypeId::M_SP_NA_1);
        assert_eq!(TypeId::from_u8(13), TypeId::M_ME_NC_1);
        assert_eq!(TypeId::from_u8(45), TypeId::C_SC_NA_1);
        assert_eq!(TypeId::from_u8(100), TypeId::C_IC_NA_1);
        assert_eq!(TypeId::from_u8(200), TypeId::Unknown(200));
    }

    #[test]
    fn test_type_id_as_str() {
        assert_eq!(TypeId::M_SP_NA_1.as_str(), "M_SP_NA_1");
        assert_eq!(TypeId::C_SC_NA_1.as_str(), "C_SC_NA_1");
        assert_eq!(TypeId::Unknown(200).as_str(), "UNKNOWN");
    }

    #[test]
    fn test_cot_cause_str() {
        let cot = CauseOfTransmission {
            cause: 3,
            negative: false,
            test: false,
            originator: 0,
        };
        assert_eq!(cot.cause_str(), "spontaneous");

        let cot2 = CauseOfTransmission {
            cause: 6,
            negative: false,
            test: false,
            originator: 0,
        };
        assert_eq!(cot2.cause_str(), "activation");
    }

    #[test]
    fn test_parse_asdu_header() {
        // TypeID=13(M_ME_NC_1), SQ=0 num=1, COT=3(spontaneous) orig=0, CommonAddr=1
        let buf = [0x0D, 0x01, 0x03, 0x00, 0x01, 0x00];
        let (rem, (type_id, is_seq, num, cot, addr)) = parse_asdu_header(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(type_id, TypeId::M_ME_NC_1);
        assert!(!is_seq);
        assert_eq!(num, 1);
        assert_eq!(cot.cause, 3);
        assert!(!cot.negative);
        assert!(!cot.test);
        assert_eq!(cot.originator, 0);
        assert_eq!(addr, 1);
    }

    #[test]
    fn test_parse_asdu_header_with_sq() {
        // TypeID=1(M_SP_NA_1), SQ=1 num=3, COT=20 orig=0, CommonAddr=1
        let buf = [0x01, 0x83, 0x14, 0x00, 0x01, 0x00];
        let (rem, (type_id, is_seq, num, cot, addr)) = parse_asdu_header(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(type_id, TypeId::M_SP_NA_1);
        assert!(is_seq);
        assert_eq!(num, 3);
        assert_eq!(cot.cause, 20);
        assert_eq!(addr, 1);
    }

    #[test]
    fn test_parse_cp56time2a() {
        // 7 bytes: ms=1000 (0xE8,0x03), min=30, hour=12, day=15|dow=3, month=6, year=24
        let buf = [0xE8, 0x03, 0x1E, 0x0C, 0x6F, 0x06, 0x18];
        let (rem, ts) = parse_cp56time2a(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(ts.ms, 1000);
        assert_eq!(ts.minute, 30);
        assert!(!ts.iv);
        assert_eq!(ts.hour, 12);
        assert_eq!(ts.day, 15);
        assert_eq!(ts.dow, 3);
        assert_eq!(ts.month, 6);
        assert_eq!(ts.year, 24);
    }

    #[test]
    fn test_parse_cp24time2a() {
        let buf = [0xE8, 0x03, 0x1E];
        let (rem, ts) = parse_cp24time2a(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(ts.ms, 1000);
        assert_eq!(ts.minute, 30);
        assert!(!ts.iv);
    }

    #[test]
    fn test_parse_single_point_asdu() {
        // Complete ASDU: TypeID=1, SQ=0, num=1, COT=3, CommonAddr=1, IOA=100, SIQ=0x01
        let buf = [
            0x01, 0x01, 0x03, 0x00, 0x01, 0x00, // header
            0x64, 0x00, 0x00, // IOA=100
            0x01, // SIQ: SPI=1, quality=0
        ];
        let (rem, asdu) = parse_asdu(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(asdu.type_id, TypeId::M_SP_NA_1);
        assert_eq!(asdu.num_objects, 1);
        assert_eq!(asdu.objects.len(), 1);
        assert_eq!(asdu.objects[0].ioa, 100);
        match &asdu.objects[0].value {
            InformationValue::SinglePoint { spi, quality } => {
                assert!(*spi);
                assert_eq!(*quality, 0);
            }
            _ => panic!("Expected SinglePoint"),
        }
    }

    #[test]
    fn test_parse_short_float_asdu() {
        // TypeID=13(M_ME_NC_1), SQ=0, num=1, COT=3, CommonAddr=1
        // IOA=16384 (0x00,0x40,0x00), float=23.5 (0x00 0x00 0xBC 0x41), QDS=0x00
        let buf = [
            0x0D, 0x01, 0x03, 0x00, 0x01, 0x00, // header
            0x00, 0x40, 0x00, // IOA=16384
            0x00, 0x00, 0xBC, 0x41, // float 23.5
            0x00, // QDS
        ];
        let (rem, asdu) = parse_asdu(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(asdu.type_id, TypeId::M_ME_NC_1);
        assert_eq!(asdu.objects.len(), 1);
        assert_eq!(asdu.objects[0].ioa, 16384);
        match &asdu.objects[0].value {
            InformationValue::ShortFloat { value, quality } => {
                assert!((value - 23.5).abs() < 0.01);
                assert_eq!(*quality, 0);
            }
            _ => panic!("Expected ShortFloat"),
        }
    }

    #[test]
    fn test_parse_single_command_asdu() {
        // TypeID=45(C_SC_NA_1), SQ=0, num=1, COT=6(activation), CommonAddr=1
        // IOA=100, SCO=0x01 (SCS=1, qualifier=0)
        let buf = [
            0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, // header
            0x64, 0x00, 0x00, // IOA=100
            0x01, // SCO
        ];
        let (rem, asdu) = parse_asdu(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(asdu.type_id, TypeId::C_SC_NA_1);
        assert_eq!(asdu.cot.cause, 6);
        match &asdu.objects[0].value {
            InformationValue::SingleCommand { scs, qualifier } => {
                assert!(*scs);
                assert_eq!(*qualifier, 0);
            }
            _ => panic!("Expected SingleCommand"),
        }
    }

    #[test]
    fn test_parse_interrogation_asdu() {
        // TypeID=100(C_IC_NA_1), SQ=0, num=1, COT=6, CommonAddr=1
        // IOA=0, QOI=20
        let buf = [
            0x64, 0x01, 0x06, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
            0x14,
        ];
        let (rem, asdu) = parse_asdu(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(asdu.type_id, TypeId::C_IC_NA_1);
        match &asdu.objects[0].value {
            InformationValue::Interrogation { qualifier } => {
                assert_eq!(*qualifier, 20);
            }
            _ => panic!("Expected Interrogation"),
        }
    }

    #[test]
    fn test_parse_sequence_mode() {
        // TypeID=1(M_SP_NA_1), SQ=1, num=3, COT=20, CommonAddr=1
        // Base IOA=100, 3 SIQ values
        let buf = [
            0x01, 0x83, 0x14, 0x00, 0x01, 0x00, // header
            0x64, 0x00, 0x00, // base IOA=100
            0x00, // SIQ[0]: SPI=0
            0x01, // SIQ[1]: SPI=1
            0x00, // SIQ[2]: SPI=0
        ];
        let (rem, asdu) = parse_asdu(&buf).unwrap();
        assert!(rem.is_empty());
        assert!(asdu.is_sequence);
        assert_eq!(asdu.objects.len(), 3);
        assert_eq!(asdu.objects[0].ioa, 100);
        assert_eq!(asdu.objects[1].ioa, 101);
        assert_eq!(asdu.objects[2].ioa, 102);
    }
}
