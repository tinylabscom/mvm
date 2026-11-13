use super::*;
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"MVMOCAP\0";
const OVERHEAD: usize = 68;
const PERMIT_BYTES: u16 = 53;
pub const MAX_ENVELOPE_BYTES: usize = CONFIG_LIMIT + OVERHEAD;

/// Untrusted startup data, not an installed capture permit.
/// A caller must establish helper compatibility before sending an encoded input.
#[derive(Debug)]
pub struct StartupEnvelope {
    config: FrozenConfig,
    call: Uuid,
    launcher_pid: u32,
}

impl FrozenConfig {
    /// Bind the original held bytes to the intended call and current launcher.
    /// No serialization or admission takes place here.
    pub fn for_call(self, call: Uuid) -> Result<StartupEnvelope> {
        let launcher_pid = std::process::id();
        if call.is_nil() || launcher_pid <= 1 {
            return Err(StartupInputError::Invalid);
        }
        Ok(StartupEnvelope {
            config: self,
            call,
            launcher_pid,
        })
    }
}

impl StartupEnvelope {
    pub fn config(&self) -> &FrozenConfig {
        &self.config
    }

    pub fn call(&self) -> Uuid {
        self.call
    }

    /// A consistency check only: the receiver observes its actual original parent.
    pub fn launcher_pid(&self) -> u32 {
        self.launcher_pid
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let config = self.config.as_bytes();
        let capacity = config
            .len()
            .checked_add(OVERHEAD)
            .ok_or(StartupInputError::Bounds)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        bytes.extend_from_slice(MAGIC);
        bytes.push(1);
        bytes.extend_from_slice(
            &u32::try_from(config.len())
                .map_err(|_| StartupInputError::Bounds)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(config);
        bytes.extend_from_slice(&PERMIT_BYTES.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(self.call.as_bytes());
        bytes.extend_from_slice(&self.config.digest());
        bytes.extend_from_slice(&self.launcher_pid.to_be_bytes());
        Ok(bytes)
    }

    /// Length/digest/schema-framing checks only. The returned record grants no
    /// authority; no process, descriptor or runtime state is touched.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(StartupInputError::Bounds);
        }
        let mut cursor = Cursor(bytes);
        if &cursor.take::<8>()? != MAGIC || cursor.take::<1>()? != [1] {
            return Err(StartupInputError::Invalid);
        }
        let length = usize::try_from(u32::from_be_bytes(cursor.take()?))
            .map_err(|_| StartupInputError::Bounds)?;
        if length == 0 || length > CONFIG_LIMIT {
            return Err(StartupInputError::Bounds);
        }
        let config_bytes = cursor.slice(length)?;
        if u16::from_be_bytes(cursor.take()?) != PERMIT_BYTES || cursor.take::<1>()? != [1] {
            return Err(StartupInputError::Invalid);
        }
        let call = Uuid::from_bytes(cursor.take()?);
        let digest: [u8; 32] = cursor.take()?;
        let launcher_pid = u32::from_be_bytes(cursor.take()?);
        if !cursor.0.is_empty() || call.is_nil() || launcher_pid <= 1 {
            return Err(StartupInputError::Invalid);
        }
        if <[u8; 32]>::from(Sha256::digest(config_bytes)) != digest {
            return Err(StartupInputError::Binding);
        }
        let config = FrozenConfig::from_json(config_bytes.to_vec())?;
        Ok(Self {
            config,
            call,
            launcher_pid,
        })
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn slice(&mut self, length: usize) -> Result<&'a [u8]> {
        let value = self.0.get(..length).ok_or(StartupInputError::Bounds)?;
        self.0 = &self.0[length..];
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.slice(N)?
            .try_into()
            .map_err(|_| StartupInputError::Bounds)
    }
}
