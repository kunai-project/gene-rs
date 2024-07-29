use std::{
    borrow::Cow,
    num::{ParseFloatError, ParseIntError, TryFromIntError},
    ops::BitAnd,
    str::FromStr,
};

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum NumberError {
    #[error("")]
    InvalidConvertion,
    #[error("{0}")]
    TryFromInt(#[from] TryFromIntError),
    #[error("{0}")]
    ParseInt(#[from] ParseIntError),
    #[error("{0}")]
    ParseFloat(#[from] ParseFloatError),
}

/// Represents any kind of number. Do not construct enum variants
/// by yourself because there is some logic behind the variant attribution.
/// For instance an positive i64 will end up being a Uint variant. So,
/// if a Number enum needs to be constructed use `from` implementations
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Number {
    Int(i64),
    Uint(u64),
    Float(f64),
}

impl TryFrom<Number> for i64 {
    type Error = NumberError;
    fn try_from(value: Number) -> Result<Self, Self::Error> {
        match value {
            Number::Float(v) => {
                if v >= i64::MIN as f64 && v <= i64::MAX as f64 {
                    return Ok(v as i64);
                }
                Err(NumberError::InvalidConvertion)
            }
            Number::Uint(v) => v.try_into().map_err(NumberError::TryFromInt),
            Number::Int(v) => Ok(v),
        }
    }
}

impl TryFrom<Number> for u64 {
    type Error = NumberError;
    fn try_from(value: Number) -> Result<Self, Self::Error> {
        match value {
            Number::Float(v) => {
                if v >= 0.0 && v <= u64::MAX as f64 {
                    return Ok(v as u64);
                }
                Err(NumberError::InvalidConvertion)
            }
            Number::Uint(v) => Ok(v),
            Number::Int(v) => v.try_into().map_err(NumberError::TryFromInt),
        }
    }
}

impl TryFrom<Number> for f64 {
    type Error = NumberError;
    fn try_from(value: Number) -> Result<Self, Self::Error> {
        match value {
            Number::Float(v) => Ok(v),
            _ => Err(NumberError::InvalidConvertion),
        }
    }
}

impl std::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Float(v) => write!(f, "{}", v),
            Self::Uint(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
        }
    }
}

impl BitAnd for Number {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        if let (Self::Int(s), Self::Int(o)) = (&self, &rhs) {
            return Self::Int(s & o);
        }

        if let (Self::Uint(s), Self::Uint(o)) = (&self, &rhs) {
            return Self::Uint(s & o);
        }

        if matches!(self, Self::Float(_)) || matches!(rhs, Self::Float(_)) {
            panic!("cannot bitand floats")
        }

        panic!("numbers needs to be of the same type")
    }
}

macro_rules! impl_unsigned_number {
    ($($src:ty),*) => {
        $(impl From<$src> for Number {
            #[inline(always)]
            fn from(value: $src) -> Self {
                Self::Uint(value as u64)
            }
        })*
    };
}

macro_rules! impl_signed_number {
    ($($src:ty),*) => {
        $(impl From<$src> for Number {
            #[inline(always)]
            fn from(value: $src) -> Self {
                if value < 0 {
                    return Self::Int(value as i64);
                }
                Self::Uint(value as u64)
            }
        })*
    };
}

impl_unsigned_number!(u8, u16, u32, u64, usize);
impl_signed_number!(i8, i16, i32, i64, isize);

impl From<f32> for Number {
    #[inline(always)]
    fn from(value: f32) -> Self {
        Self::from(value as f64)
    }
}

impl From<f64> for Number {
    #[inline(always)]
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl FromStr for Number {
    type Err = NumberError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Number {
    pub fn parse<S: AsRef<str>>(s: S) -> Result<Self, NumberError> {
        let s = s.as_ref();
        // looks like an hexadecimal value
        if s.starts_with("0x") {
            // unwrap cannot fail as we are sure s has 0x prefix
            return Ok(u64::from_str_radix(s.strip_prefix("0x").unwrap(), 16)?.into());
        }

        // is negative
        if s.starts_with('-') {
            // is floating number
            if s.contains('.') {
                return Ok(f64::from_str(s)?.into());
            }
            // if negative and not floating
            return Ok(i64::from_str(s)?.into());
        }

        // is floating number
        if s.contains('.') {
            return Ok(f64::from_str(s)?.into());
        }
        // if positive and not floating
        Ok(u64::from_str(s)?.into())
    }

    #[inline(always)]
    pub fn is_uint(&self) -> bool {
        matches!(self, Self::Uint(_))
    }

    #[inline(always)]
    pub fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    #[inline(always)]
    pub fn is_int(&self) -> bool {
        matches!(self, Self::Int(_))
    }
}

/// A FieldValue is an enum representing the different values
/// a field from a structure can have. Many convertions
/// from base and common types are implemented.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    String(String),
    Number(Number),
    Bool(bool),
    Some,
    None,
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "{}", s),
            Self::Number(s) => write!(f, "{}", s),
            Self::Bool(b) => write!(f, "{}", b),
            Self::Some => write!(f, "some"),
            Self::None => write!(f, "none"),
        }
    }
}

impl FieldValue {
    pub(crate) const fn type_str(&self) -> &'static str {
        match self {
            Self::Bool(_) => "bool",
            Self::String(_) => "string",
            Self::Number(_) => "number",
            Self::Some => "some",
            Self::None => "none",
        }
    }

    pub(crate) fn try_into_number(self) -> Result<Self, NumberError> {
        match self {
            Self::Number(_) => Ok(self),
            Self::String(s) => Ok(Self::Number(Number::from_str(&s)?)),
            Self::Bool(b) => Ok(Self::Number((b as u8).into())),
            Self::None | Self::Some => Err(NumberError::InvalidConvertion),
        }
    }

    pub(crate) const fn is_string(&self) -> bool {
        matches!(self, FieldValue::String(_))
    }

    #[inline(always)]
    pub(crate) const fn is_some(&self) -> bool {
        !self.is_none()
    }

    #[inline(always)]
    pub(crate) const fn is_none(&self) -> bool {
        matches!(self, FieldValue::None)
    }
}

macro_rules! impl_field_value_number {
    ($($src:ty),*) => {
        $(
        impl From<$src> for FieldValue {
            fn from(value: $src) -> Self {
                Self::Number(value.into())
            }
        }
        )*
    };
}

impl_field_value_number!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, f32, f64);

impl From<Cow<'_, str>> for FieldValue {
    fn from(value: Cow<'_, str>) -> Self {
        Self::String(value.into())
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::String(value.into())
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl<T> From<Option<T>> for FieldValue
where
    T: Into<FieldValue>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(b) => b.into(),
            None => Self::None,
        }
    }
}

impl<T> From<&Option<T>> for FieldValue
where
    T: Into<FieldValue> + Clone,
{
    fn from(value: &Option<T>) -> Self {
        match value {
            Some(b) => b.clone().into(),
            None => Self::None,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_number() {
        let a = Number::from(42u8);
        assert!(a.is_uint());
        let b = Number::from(42isize);
        // every positive int is converted to uint
        assert!(b.is_uint());
        let c = Number::from(4242);
        assert!(Number::from(-42).is_int());
        assert_eq!(a, b);
        assert!(a < c);
        assert!(c > b);

        let f = Number::from(42.0);
        assert!(f.is_float());

        let e = Number::from(0x40_u32);
        assert!(Number::from(0x100040) & e == e);
        assert!(Number::from(0x100020) & e != e);

        assert_eq!(Number::from_str("-1").unwrap(), Number::from(-1));
        assert_eq!(Number::from_str("0.41").unwrap(), Number::from(0.41));
    }

    #[test]
    fn test_field_value() {
        // testing convertion to numbers
        assert_eq!(
            FieldValue::String("42.0".into()).try_into_number().unwrap(),
            FieldValue::Number(42.0.into())
        );

        assert_eq!(
            FieldValue::String("-0.42".into())
                .try_into_number()
                .unwrap(),
            FieldValue::Number(Number::from(-0.42))
        );

        assert_eq!(
            FieldValue::String("-42".into()).try_into_number().unwrap(),
            FieldValue::Number(Number::from(-42))
        );

        // convertion from bool should work too
        assert_eq!(
            FieldValue::Bool(true).try_into_number().unwrap(),
            FieldValue::Number(Number::from(1))
        );

        assert_eq!(
            FieldValue::Bool(false).try_into_number().unwrap(),
            FieldValue::Number(Number::from(0))
        );
    }
}
