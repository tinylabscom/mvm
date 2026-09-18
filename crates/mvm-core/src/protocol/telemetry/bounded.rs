//! Allocation-conscious containers for the telemetry worker boundary.
//! Constructors bound owned storage; wire decoding additionally bounds input bytes.

use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, de};

use super::RecordError;

/// UTF-8 text with a byte ceiling, checked before copying borrowed input.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Text<const N: usize>(String);

impl<const N: usize> Text<N> {
    /// Copy at most `N` bytes. Oversize input is rejected, not truncated silently.
    pub fn new(value: &str) -> Result<Self, RecordError> {
        if value.len() > N {
            return Err(RecordError::Capacity);
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the text. Treat it as untrusted even after structural validation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Text")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl<const N: usize> TryFrom<&str> for Text<N> {
    type Error = RecordError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Text<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<const N: usize>;
        impl<const N: usize> de::Visitor<'_> for Visitor<N> {
            type Value = Text<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded telemetry text")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Text::new(value).map_err(E::custom)
            }
        }
        d.deserialize_str(Visitor::<N>)
    }
}

/// Owned list whose element count cannot exceed `N`.
/// Each element must itself have a bound; this is not a byte-budget by itself.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BoundedList<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedList<T, N> {
    /// Take ownership of a list, refusing excess elements.
    pub fn new(values: Vec<T>) -> Result<Self, RecordError> {
        if values.len() > N {
            return Err(RecordError::Capacity);
        }
        // Do not retain a caller's arbitrarily oversized backing allocation.
        Ok(Self(values.into_boxed_slice().into_vec()))
    }

    /// Borrow the bounded elements.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> Default for BoundedList<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const N: usize> fmt::Debug for BoundedList<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedList")
            .field("len", &self.0.len())
            .finish()
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedList<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> de::Visitor<'de> for Visitor<T, N> {
            type Value = BoundedList<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded telemetry list")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while values.len() < N {
                    match seq.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(BoundedList(values)),
                    }
                }
                // Reject the extra element without deserializing/allocating its body.
                struct Reject;
                impl<'de> Deserialize<'de> for Reject {
                    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
                        Err(de::Error::custom("telemetry list capacity exceeded"))
                    }
                }
                let _: Option<Reject> = seq.next_element()?;
                Ok(BoundedList(values))
            }
        }
        d.deserialize_seq(Visitor::<T, N>(PhantomData))
    }
}
