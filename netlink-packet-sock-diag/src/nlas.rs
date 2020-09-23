use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};

pub use crate::utils::nla::{DefaultNla, NlaBuffer, NlasIterator};

use crate::{constants::*, parsers::parse_u32, traits::Parseable, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BpfStorageRequestNla {
    /// descriptor of the bpf_sk_storage to be dumped
    MapFd(u32),
    /// other attribute
    Other(DefaultNla),
}

impl crate::utils::nla::Nla for BpfStorageRequestNla {
    fn value_len(&self) -> usize {
        use self::BpfStorageRequestNla::*;
        match *self {
            MapFd(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::BpfStorageRequestNla::*;
        match *self {
            MapFd(value) => NativeEndian::write_u32(buffer, value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::BpfStorageRequestNla::*;
        match *self {
            MapFd(_) => SK_DIAG_BPF_STORAGE_REQ_MAP_FD,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for BpfStorageRequestNla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SK_DIAG_BPF_STORAGE_REQ_MAP_FD => Self::MapFd(
                parse_u32(payload).context("invalid SK_DIAG_BPF_STORAGE_REQ_MAP_FD value")?,
            ),
            kind => {
                Self::Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?)
            }
        })
    }
}
