// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from apple-codesign 0.29.0 plist_der.rs, Copyright Gregory Szorc.
// See ../PROVENANCE.md.

use crate::{Error, Result};
use plist::Value;

fn tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![tag];
    if payload.len() < 128 {
        data.push(payload.len() as u8);
    } else {
        let length = payload.len().to_be_bytes();
        let start = length.iter().position(|b| *b != 0).expect("nonzero length");
        data.push(0x80 | (length.len() - start) as u8);
        data.extend_from_slice(&length[start..]);
    }
    data.extend_from_slice(payload);
    data
}
fn encode(value: &Value, depth: usize) -> Result<Vec<u8>> {
    if depth > 64 {
        return Err("DER nesting exceeds limit".into());
    }
    Ok(match value {
        Value::Boolean(value) => tlv(1, &[if *value { 255 } else { 0 }]),
        Value::String(value) => tlv(12, value.as_bytes()),
        Value::Integer(value) => {
            let bytes = value
                .as_signed()
                .ok_or("DER integer exceeds signed i64")?
                .to_be_bytes();
            let mut start = 0;
            while start < 7
                && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                    || (bytes[start] == 255 && bytes[start + 1] & 0x80 != 0))
            {
                start += 1;
            }
            tlv(2, &bytes[start..])
        }
        Value::Array(values) => {
            let mut payload = Vec::new();
            for value in values {
                payload.extend_from_slice(&encode(value, depth + 1)?);
            }
            tlv(0x30, &payload)
        }
        Value::Dictionary(dict) => {
            let mut payload = Vec::new();
            for (key, value) in dict.iter().collect::<std::collections::BTreeMap<_, _>>() {
                let mut entry = tlv(12, key.as_bytes());
                entry.extend_from_slice(&encode(value, depth + 1)?);
                payload.extend_from_slice(&tlv(0x30, &entry));
            }
            tlv(0xb0, &payload)
        }
        _ => return Err("unsupported DER entitlement plist type".into()),
    })
}
pub fn encode_entitlements_der(value: &Value) -> Result<Vec<u8>> {
    if value.as_dictionary().is_none() {
        return Err("entitlements must be a dictionary".into());
    }
    let mut payload = vec![2, 1, 1];
    payload.extend_from_slice(&encode(value, 0)?);
    Ok(tlv(0x70, &payload))
}
fn take<'a>(data: &mut &'a [u8]) -> Result<(u8, &'a [u8])> {
    let tag = *data.first().ok_or("truncated DER tag")?;
    let first = *data.get(1).ok_or("truncated DER length")?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err("invalid DER length".into());
        }
        let bytes = data.get(2..2 + count).ok_or("truncated DER length")?;
        if bytes[0] == 0 {
            return Err("nonminimal DER length".into());
        }
        let mut length = 0usize;
        for byte in bytes {
            length = length
                .checked_mul(256)
                .and_then(|x| x.checked_add(*byte as usize))
                .ok_or("DER length overflow")?;
        }
        if length < 128 {
            return Err("nonminimal DER length".into());
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length).ok_or("DER length overflow")?;
    let payload = data.get(header..end).ok_or("truncated DER value")?;
    *data = data.get(end..).ok_or("truncated DER value")?;
    Ok((tag, payload))
}
fn decode(data: &mut &[u8], depth: usize) -> Result<Value> {
    if depth > 64 {
        return Err("DER nesting exceeds limit".into());
    }
    let (tag, mut payload) = take(data)?;
    Ok(match tag {
        1 => match payload {
            [0] => Value::Boolean(false),
            [255] => Value::Boolean(true),
            _ => return Err("invalid DER boolean".into()),
        },
        12 => Value::String(
            std::str::from_utf8(payload)
                .map_err(|e| Error::from(e.to_string()))?
                .into(),
        ),
        2 => {
            if payload.is_empty() || payload.len() > 8 {
                return Err("invalid DER integer".into());
            }
            if payload.len() > 1
                && ((payload[0] == 0 && payload[1] & 0x80 == 0)
                    || (payload[0] == 255 && payload[1] & 0x80 != 0))
            {
                return Err("nonminimal DER integer".into());
            }
            let mut bytes = [if payload[0] & 0x80 == 0 { 0 } else { 255 }; 8];
            bytes[8 - payload.len()..].copy_from_slice(payload);
            Value::Integer(i64::from_be_bytes(bytes).into())
        }
        0x30 => {
            let mut values = Vec::new();
            while !payload.is_empty() {
                values.push(decode(&mut payload, depth + 1)?);
            }
            Value::Array(values)
        }
        0xb0 => {
            let mut dict = plist::Dictionary::new();
            while !payload.is_empty() {
                let (tag, mut entry) = take(&mut payload)?;
                if tag != 0x30 {
                    return Err("invalid DER dictionary entry".into());
                }
                let (tag, key) = take(&mut entry)?;
                if tag != 12 {
                    return Err("invalid DER dictionary key".into());
                }
                let key = std::str::from_utf8(key).map_err(|e| Error::from(e.to_string()))?;
                let value = decode(&mut entry, depth + 1)?;
                if !entry.is_empty() || dict.insert(key.into(), value).is_some() {
                    return Err("duplicate key or trailing DER dictionary data".into());
                }
            }
            Value::Dictionary(dict)
        }
        _ => return Err("unsupported DER entitlement tag".into()),
    })
}
pub fn decode_entitlements_der(mut data: &[u8]) -> Result<Value> {
    let (tag, mut payload) = take(&mut data)?;
    if tag != 0x70 || !data.is_empty() {
        return Err("invalid DER plist wrapper".into());
    }
    let (tag, version) = take(&mut payload)?;
    if tag != 2 || version != [1] {
        return Err("unsupported DER plist version".into());
    }
    let value = decode(&mut payload, 0)?;
    if !payload.is_empty() || value.as_dictionary().is_none() {
        return Err("invalid DER plist payload".into());
    }
    Ok(value)
}
