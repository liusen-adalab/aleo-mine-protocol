use std::io::Write;

use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use snarkvm::{
    dpc::{testnet2::Testnet2, Address, BlockTemplate, PoSWProof},
    traits::Network,
    utilities::{FromBytes, ToBytes},
};
use tokio_util::codec::{Decoder, Encoder};

#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Eq, Debug)]
pub enum PoolMessage {
    // as in stratum, with an additional protocol version field
    Authorize(Address<Testnet2>, String, u16),
    AuthorizeResult(bool, Option<String>),

    // combine notify and set_difficulty to be consistent
    Notify(BlockTemplate<Testnet2>, u64),
    // include block height to detect stales faster
    Submit(u32, <Testnet2 as Network>::PoSWNonce, PoSWProof<Testnet2>),
    // miners might want to know the stale rate, optionally provide a message
    SubmitResult(bool, Option<String>),
    ProverNumMinute(u64),

    Exit,

    Canary,
}

#[allow(dead_code)]
static VERSION: u16 = 1;

impl PoolMessage {
    #[allow(dead_code)]
    pub fn version() -> &'static u16 {
        &VERSION
    }

    pub fn id(&self) -> u8 {
        match self {
            PoolMessage::Authorize(..) => 0,
            PoolMessage::AuthorizeResult(..) => 1,
            PoolMessage::Notify(..) => 2,
            PoolMessage::Submit(..) => 3,
            PoolMessage::SubmitResult(..) => 4,

            PoolMessage::Canary => 5,
            PoolMessage::ProverNumMinute(_) => 7,
            PoolMessage::Exit => 8,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            PoolMessage::Authorize(..) => "Authorize",
            PoolMessage::AuthorizeResult(..) => "AuthorizeResult",
            PoolMessage::Notify(..) => "Notify",
            PoolMessage::Submit(..) => "Submit",
            PoolMessage::SubmitResult(..) => "SubmitResult",
            PoolMessage::Canary => "Canary",
            PoolMessage::ProverNumMinute(_) => "prover_num_in_minute",
            PoolMessage::Exit => "exit",
        }
    }
}

impl Encoder<PoolMessage> for PoolMessage {
    type Error = anyhow::Error;

    fn encode(&mut self, item: PoolMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&0u32.to_le_bytes());
        let mut writer = dst.writer();
        writer.write_all(&[item.id()])?;
        match item {
            PoolMessage::Authorize(addr, password, version) => {
                bincode::serialize_into(&mut writer, &addr)?;
                bincode::serialize_into(&mut writer, &password)?;
                writer.write_all(&version.to_le_bytes())?;
            }
            PoolMessage::AuthorizeResult(result, message)
            | PoolMessage::SubmitResult(result, message) => {
                writer.write_all(&[match result {
                    true => 1,
                    false => 0,
                }])?;
                if let Some(message) = message {
                    writer.write_all(&[1])?;
                    bincode::serialize_into(&mut writer, &message)?;
                } else {
                    writer.write_all(&[0])?;
                }
            }
            PoolMessage::Notify(template, difficulty) => {
                template.write_le(&mut writer)?;
                writer.write_all(&difficulty.to_le_bytes())?;
            }
            PoolMessage::Submit(height, nonce, proof) => {
                writer.write_all(&height.to_le_bytes())?;
                nonce.write_le(&mut writer)?;
                proof.write_le(&mut writer)?;
            }
            PoolMessage::Canary => return Err(anyhow!("Use of unsupported message")),
            PoolMessage::ProverNumMinute(num) => {
                writer.write_all(&num.to_le_bytes())?;
            }
            PoolMessage::Exit => {}
        }
        let msg_len = dst.len() - 4;
        dst[..4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        Ok(())
    }
}

impl Decoder for PoolMessage {
    type Error = anyhow::Error;
    type Item = PoolMessage;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        if length > 1048576 {
            return Err(anyhow!("Message too long"));
        }
        if src.len() < 4 + length {
            return Ok(None);
        }

        let reader = &mut src.reader();
        reader.read_u32::<LittleEndian>()?;
        let msg_id = reader.read_u8()?;
        let msg = match msg_id {
            0 => {
                let addr = bincode::deserialize_from(&mut *reader)?;
                let password = bincode::deserialize_from(&mut *reader)?;
                let version = reader.read_u16::<LittleEndian>()?;
                PoolMessage::Authorize(addr, password, version)
            }
            1 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                PoolMessage::AuthorizeResult(result, message)
            }
            2 => {
                let template = BlockTemplate::<Testnet2>::read_le(&mut *reader)?;
                let difficulty = reader.read_u64::<LittleEndian>()?;
                PoolMessage::Notify(template, difficulty)
            }
            3 => {
                let height = reader.read_u32::<LittleEndian>()?;
                let nonce = <Testnet2 as Network>::PoSWNonce::read_le(&mut *reader)?;
                let proof = PoSWProof::<Testnet2>::read_le(&mut *reader)?;
                PoolMessage::Submit(height, nonce, proof)
            }
            4 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                PoolMessage::SubmitResult(result, message)
            }
            7 => {
                let num = reader.read_u64::<LittleEndian>()?;
                PoolMessage::ProverNumMinute(num)
            }
            8 => PoolMessage::Exit,
            _ => {
                return Err(anyhow!("Unknown message id: {}", msg_id));
            }
        };
        Ok(Some(msg))
    }
}

pub enum WorkerMessage {
    NewWork(u64, BlockTemplate<Testnet2>),
    Result(bool, Option<String>),
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use crate::PoolMessage;

    #[test]
    fn test_codec() {
        {
            let mut canary = PoolMessage::Canary;
            let msg = PoolMessage::Exit;

            let mut bytes = BytesMut::new();
            canary.encode(msg, &mut bytes).unwrap();
            let decoded = canary.decode(&mut bytes).unwrap().unwrap();

            assert_eq!(decoded, PoolMessage::Exit);
        }

        {
            let mut canary = PoolMessage::Canary;
            let msg = PoolMessage::ProverNumMinute(10);

            let mut bytes = BytesMut::new();
            canary.encode(msg, &mut bytes).unwrap();
            let decoded = canary.decode(&mut bytes).unwrap().unwrap();

            assert_eq!(decoded, PoolMessage::ProverNumMinute(10));
        }
    }
}
