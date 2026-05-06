//! Internal MMS PDU parser error taxonomy.

#![allow(dead_code)]

/// Internal parser error used by future parser internals.
///
/// The public `parse_mms_pdu` contract remains `Result<MmsPdu, ()>` during the
/// structure-first refactor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MmsParseError {
    Malformed(&'static str),
    Unsupported(&'static str),
    SemanticViolation(&'static str),
    DepthLimit,
}

pub(super) type MmsParseResult<T> = Result<T, MmsParseError>;

impl MmsParseError {
    pub(super) fn malformed(reason: &'static str) -> Self {
        Self::Malformed(reason)
    }

    pub(super) fn unsupported(reason: &'static str) -> Self {
        Self::Unsupported(reason)
    }

    pub(super) fn semantic_violation(reason: &'static str) -> Self {
        Self::SemanticViolation(reason)
    }

    pub(super) fn depth_limit() -> Self {
        Self::DepthLimit
    }
}
