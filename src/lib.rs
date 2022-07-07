use std::io::Write;

use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use snarkvm::{
    dpc::{testnet2::Testnet2, Address, BlockTemplate, Network, PoSWProof},
    utilities::{FromBytes, ToBytes},
};
use tokio_util::codec::{Decoder, Encoder};

#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Eq, Debug)]
pub enum Message {
    // as in stratum, with an additional protocol version field
    Authorize(Address<Testnet2>, String, u16),
    AuthorizeResult(bool, Option<String>),

    // combine notify and set_difficulty to be consistent
    Notify(BlockTemplate<Testnet2>, u64),
    // include block height to detect stales faster
    Submit(u32, <Testnet2 as Network>::PoSWNonce, PoSWProof<Testnet2>),
    // miners might want to know the stale rate, optionally provide a message
    SubmitResult(bool, Option<String>),
    ProvePerMinute(u64),

    Canary,
}

#[allow(dead_code)]
static VERSION: u16 = 1;

impl Message {
    #[allow(dead_code)]
    pub fn version() -> &'static u16 {
        &VERSION
    }

    pub fn id(&self) -> u8 {
        match self {
            Message::Authorize(..) => 0,
            Message::AuthorizeResult(..) => 1,
            Message::Notify(..) => 2,
            Message::Submit(..) => 3,
            Message::SubmitResult(..) => 4,

            Message::Canary => 5,
            Message::ProvePerMinute(_) => 6,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Message::Authorize(..) => "Authorize",
            Message::AuthorizeResult(..) => "AuthorizeResult",
            Message::Notify(..) => "Notify",
            Message::Submit(..) => "Submit",
            Message::SubmitResult(..) => "SubmitResult",
            Message::Canary => "Canary",
            Message::ProvePerMinute(_) => "prover_num_in_minute",
        }
    }
}

impl Encoder<Message> for Message {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&0u32.to_le_bytes());
        let mut writer = dst.writer();
        writer.write_all(&[item.id()])?;
        match item {
            Message::Authorize(addr, password, version) => {
                bincode::serialize_into(&mut writer, &addr)?;
                bincode::serialize_into(&mut writer, &password)?;
                writer.write_all(&version.to_le_bytes())?;
            }
            Message::AuthorizeResult(result, message) | Message::SubmitResult(result, message) => {
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
            Message::Notify(template, difficulty) => {
                template.write_le(&mut writer)?;
                writer.write_all(&difficulty.to_le_bytes())?;
            }
            Message::Submit(height, nonce, proof) => {
                writer.write_all(&height.to_le_bytes())?;
                nonce.write_le(&mut writer)?;
                proof.write_le(&mut writer)?;
            }
            Message::Canary => return Err(anyhow!("Use of unsupported message")),
            Message::ProvePerMinute(num) => {
                writer.write_all(&num.to_le_bytes())?;
            }
        }
        let msg_len = dst.len() - 4;
        dst[..4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        Ok(())
    }
}

impl Decoder for Message {
    type Error = anyhow::Error;
    type Item = Message;

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
                Message::Authorize(addr, password, version)
            }
            1 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                Message::AuthorizeResult(result, message)
            }
            2 => {
                let template = BlockTemplate::<Testnet2>::read_le(&mut *reader)?;
                let difficulty = reader.read_u64::<LittleEndian>()?;
                Message::Notify(template, difficulty)
            }
            3 => {
                let height = reader.read_u32::<LittleEndian>()?;
                let nonce = <Testnet2 as Network>::PoSWNonce::read_le(&mut *reader)?;
                let proof = PoSWProof::<Testnet2>::read_le(&mut *reader)?;
                Message::Submit(height, nonce, proof)
            }
            4 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                Message::SubmitResult(result, message)
            }
            5 => {
                return Err(anyhow!("cannot decode canary"));
            }
            6 => {
                let num = reader.read_u64::<LittleEndian>()?;
                Message::ProvePerMinute(num)
            }
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

    use crate::Message;

    #[test]
    fn test_codec() {
        let mut canary = Message::Canary;
        let msg = Message::ProvePerMinute(10);

        let mut bytes = BytesMut::new();
        canary.encode(msg, &mut bytes).unwrap();
        let decoded = canary.decode(&mut bytes).unwrap().unwrap();

        assert_eq!(decoded, Message::ProvePerMinute(10));
    }
}
