use super::*;
use crate::plan::Nonce;

pub(super) const DOMAIN: &[u8] = b"mvm.owned-hvf.capture-possession.v1\0";

pub(super) fn label(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(CaptureProofError::Bounds);
    }
    if value.chars().any(char::is_control) {
        return Err(CaptureProofError::Invalid);
    }
    Ok(())
}

pub(super) fn digest<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CaptureProofError::Invalid);
    }
    let mut decoded = [0; N];
    hex::decode_to_slice(value, &mut decoded).map_err(|_| CaptureProofError::Invalid)?;
    Ok(decoded)
}

pub(super) fn plan_digest(value: &str) -> Result<[u8; 32]> {
    digest(
        value
            .strip_prefix("sha256:")
            .ok_or(CaptureProofError::Invalid)?,
    )
}

fn put_text(body: &mut Vec<u8>, text: &str) -> Result<()> {
    let length = u16::try_from(text.len()).map_err(|_| CaptureProofError::Bounds)?;
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    Ok(())
}

// Callers validate before encoding. Tests also use this to construct malformed claims.
pub(super) fn body(challenge: &CaptureChallenge) -> Result<Vec<u8>> {
    let binding = &challenge.binding;
    let registration = &binding.registration;
    let mut body = vec![1];
    body.extend_from_slice(binding.identity.installation.as_bytes());
    body.extend_from_slice(&binding.identity.public_key);
    put_text(&mut body, &registration.tenant)?;
    put_text(&mut body, &binding.vm)?;
    body.extend_from_slice(&plan_digest(&registration.plan_id)?);
    body.extend_from_slice(&digest::<16>(registration.plan_nonce.as_hex())?);
    body.extend_from_slice(&binding.startup);
    put_text(&mut body, &registration.instance)?;
    for id in [
        registration.run,
        registration.producer,
        registration.session,
        binding.call,
    ] {
        body.extend_from_slice(id.as_bytes());
    }
    body.extend_from_slice(&binding.boot);
    put_text(&mut body, &binding.capture_run)?;
    body.extend_from_slice(&binding.producer_pid.to_be_bytes());
    body.extend_from_slice(&binding.supervisor_pid.to_be_bytes());
    body.extend_from_slice(&challenge.nonce);
    body.extend_from_slice(&challenge.issued.to_be_bytes());
    body.extend_from_slice(&challenge.expires.to_be_bytes());
    Ok(body)
}

pub(super) fn message(challenge: &CaptureChallenge) -> Result<Vec<u8>> {
    Ok([DOMAIN, &body(challenge)?].concat())
}

pub(super) fn frame(tag: u8, challenge: &CaptureChallenge, signature: &[u8]) -> Result<Vec<u8>> {
    let body = body(challenge)?;
    let length = 1_usize
        .checked_add(body.len())
        .and_then(|n| n.checked_add(signature.len()))
        .ok_or(CaptureProofError::Bounds)?;
    if length.checked_add(4).ok_or(CaptureProofError::Bounds)? > MAX_FRAME_BYTES {
        return Err(CaptureProofError::Bounds);
    }
    let mut bytes = u32::try_from(length)
        .map_err(|_| CaptureProofError::Bounds)?
        .to_be_bytes()
        .to_vec();
    bytes.push(tag);
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(signature);
    Ok(bytes)
}

pub(super) fn unframe(bytes: &[u8], tag: u8) -> Result<&[u8]> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(CaptureProofError::Bounds);
    }
    let mut cursor = Cursor(bytes);
    let length = usize::try_from(u32::from_be_bytes(cursor.take()?))
        .map_err(|_| CaptureProofError::Bounds)?;
    if length.checked_add(4) != Some(bytes.len()) {
        return Err(CaptureProofError::Bounds);
    }
    if cursor.take::<1>()? != [tag] {
        return Err(CaptureProofError::Invalid);
    }
    Ok(cursor.0)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.0.get(..N).ok_or(CaptureProofError::Bounds)?;
        let value = bytes.try_into().map_err(|_| CaptureProofError::Bounds)?;
        self.0 = &self.0[N..];
        Ok(value)
    }

    fn text(&mut self, maximum: usize) -> Result<String> {
        let length = usize::from(u16::from_be_bytes(self.take()?));
        if length == 0 || length > maximum {
            return Err(CaptureProofError::Bounds);
        }
        let bytes = self.0.get(..length).ok_or(CaptureProofError::Bounds)?;
        let value = std::str::from_utf8(bytes).map_err(|_| CaptureProofError::Invalid)?;
        self.0 = &self.0[length..];
        Ok(value.into())
    }
}

pub(super) fn parse(bytes: &[u8], expected: &CaptureBinding) -> Result<CaptureChallenge> {
    let mut cursor = Cursor(bytes);
    if cursor.take::<1>()? != [1] {
        return Err(CaptureProofError::Invalid);
    }
    let identity = EnrolledIdentity {
        installation: Uuid::from_bytes(cursor.take()?),
        public_key: cursor.take()?,
    };
    let tenant = cursor.text(512)?;
    let vm = cursor.text(512)?;
    let plan_id = format!("sha256:{}", hex::encode(cursor.take::<32>()?));
    let plan_nonce = Nonce::from_bytes(cursor.take()?);
    let startup = cursor.take()?;
    let instance = cursor.text(512)?;
    let registration = RegistrationBinding {
        tenant,
        instance,
        plan_id,
        plan_nonce,
        run: Uuid::from_bytes(cursor.take()?),
        producer: Uuid::from_bytes(cursor.take()?),
        session: Uuid::from_bytes(cursor.take()?),
        not_before: expected.registration.not_before,
        not_after: expected.registration.not_after,
    };
    let binding = CaptureBinding {
        identity,
        registration,
        vm,
        startup,
        call: Uuid::from_bytes(cursor.take()?),
        boot: cursor.take()?,
        capture_run: cursor.text(128)?,
        producer_pid: u32::from_be_bytes(cursor.take()?),
        supervisor_pid: u32::from_be_bytes(cursor.take()?),
    };
    let challenge = CaptureChallenge {
        binding,
        nonce: cursor.take()?,
        issued: u64::from_be_bytes(cursor.take()?),
        expires: u64::from_be_bytes(cursor.take()?),
    };
    if !cursor.0.is_empty() {
        return Err(CaptureProofError::Invalid);
    }
    Ok(challenge)
}
