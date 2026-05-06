//! Lightweight parser context for future MMS PDU parser internals.

#![allow(dead_code)]

use crate::iec61850mms::ber::MAX_BER_DEPTH;

/// Parser traversal context.
///
/// Phase 1 introduces this as a skeleton only. Existing parser functions keep
/// their current signatures until module seams are stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParseCtx {
    depth: usize,
    max_depth: usize,
}

impl ParseCtx {
    pub(super) fn new() -> Self {
        Self {
            depth: 0,
            max_depth: MAX_BER_DEPTH,
        }
    }

    pub(super) fn with_depth(depth: usize) -> Self {
        Self {
            depth,
            max_depth: MAX_BER_DEPTH,
        }
    }

    pub(super) fn depth(self) -> usize {
        self.depth
    }

    pub(super) fn can_descend(self) -> bool {
        self.depth < self.max_depth
    }

    pub(super) fn descend(self) -> Option<Self> {
        if self.can_descend() {
            Some(Self {
                depth: self.depth + 1,
                max_depth: self.max_depth,
            })
        } else {
            None
        }
    }
}
