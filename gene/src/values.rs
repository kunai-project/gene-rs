//! Field value representations and number handling for the Gene event scanning engine.
//!
//! This module provides types for representing field values extracted from events
//! and performing operations on them. It includes:
//!
//! - [`Number`]: Unified numeric type supporting integers and floats
//! - [`NumberError`]: Errors during number parsing and conversion
//! - [`FieldValue`]: Enum representing any field value type
//! - Conversion implementations for various Rust types
//!
//! # Number Handling
//!
//! The [`Number`] enum provides a unified representation for numeric values:
//! - Signed integers (`Int(i64)`)
//! - Unsigned integers (`Uint(u64)`)
//! - Floating-point numbers (`Float(f64)`)
//!
//! Variant selection is automatic based on value properties:
//! - Negative values → `Int(i64)`
//! - Non-negative values → `Uint(u64)`
//! - Floating-point values → `Float(f64)`
//!
//! # Field Values
//!
//! The [`FieldValue`] enum represents any value that can be extracted from an event:
//! - Strings and paths
//! - Numbers (via [`Number`])
//! - Booleans
//! - Optional values
//! - Vectors and collections
//!
//! # Usage
//!
//! ```rust
//! use gene::values::{Number, FieldValue};
//!
//! // Create numbers from various types
//! let n1: Number = 42u64.into();
//! let n2: Number = (-5i64).into();
//! let n3: Number = 3.14f64.into();
//!
//! // Parse numbers from strings
//! let n4 = Number::parse("0x1F").unwrap();
//!
//! // Create field values
//! let fv1: FieldValue = "hello".into();
//! let fv2: FieldValue = 42u64.into();
//! let fv3: FieldValue = Some("value").into();
//! ```

use std::{
    borrow::Cow,
    num::{ParseFloatError, ParseIntError, TryFromIntError},
    ops::BitAnd,
    path::PathBuf,
    str::FromStr,
};

use thiserror::Error;

/// Errors that can occur during number parsing and conversion operations.
///
/// This enum represents all possible errors that can occur when working with
/// numeric values in the engine, including parsing from strings, converting
/// between numeric types, and handling type mismatches.
#[derive(Debug, Error, PartialEq)]
pub enum NumberError {
    /// Invalid conversion between numeric types.
    ///
    /// This error occurs when a conversion between numeric types is not possible
    /// due to value constraints or type incompatibilities. For example, converting
    /// a float value that exceeds integer range.
    #[error("invalid conversion")]
    InvalidConversion,

    /// Error during integer conversion.
    ///
    /// Wraps errors from `TryFromIntError` that occur when converting between
    /// integer types or when integer values are out of range for the target type.
    #[error("{0}")]
    TryFromInt(#[from] TryFromIntError),

    /// Error during integer parsing.
    ///
    /// Wraps errors from `ParseIntError` that occur when parsing integer values
    /// from strings, such as invalid digit sequences or overflow.
    #[error("{0}")]
    ParseInt(#[from] ParseIntError),

    /// Error during float parsing.
    ///
    /// Wraps errors from `ParseFloatError` that occur when parsing floating-point
    /// values from strings, such as invalid number formats.
    #[error("{0}")]
    ParseFloat(#[from] ParseFloatError),

    /// Other number-related errors.
    ///
    /// Generic error variant for number-related issues that don't fit the
    /// specific categories above. The string contains a descriptive error message.
    #[error("other: {0}")]
    Other(String),
}

/// Represents any kind of number in the engine.
///
/// This enum provides a unified type for numeric values that can be used across
/// different rule operations and field types. It supports signed integers, unsigned
/// integers, and floating-point numbers.
///
/// # Variant Selection
///
/// The variant used for a given numeric value is determined automatically based
/// on the value's properties:
/// - Negative values become `Int(i64)`
/// - Non-negative values that fit in `u64` become `Uint(u64)`
/// - Floating-point values become `Float(f64)`
///
/// # Construction
///
/// Do not construct `Number` enum variants directly. Instead, use the `From` trait
/// implementations to ensure proper variant selection. This guarantees consistent
/// behavior across the engine.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Number {
    /// Signed integer value.
    ///
    /// Contains values that are negative or zero. Positive values that could fit
    /// in `u64` are represented as `Uint` variants instead.
    Int(i64),

    /// Unsigned integer value.
    ///
    /// Contains non-negative values that fit within the `u64` range. This variant
    /// is used for positive integers to optimize storage and comparison operations.
    Uint(u64),

    /// Floating-point value.
    ///
    /// Contains values with decimal precision. All floating-point numbers are
    /// represented using `f64` precision.
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
                Err(NumberError::InvalidConversion)
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
                Err(NumberError::InvalidConversion)
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
            _ => Err(NumberError::InvalidConversion),
        }
    }
}

impl std::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Float(v) => write!(f, "{v}"),
            Self::Uint(v) => write!(f, "{v}"),
            Self::Int(v) => write!(f, "{v}"),
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
    /// Parses a string into a `Number`.
    ///
    /// This method supports multiple numeric formats:
    /// - Decimal integers (positive and negative)
    /// - Floating-point numbers
    /// - Hexadecimal values (with `0x` prefix)
    ///
    /// The parser automatically selects the appropriate variant based on the
    /// string format and value properties. Hexadecimal values are always parsed
    /// as unsigned integers, negative values as signed integers, and values with
    /// decimal points as floating-point numbers.
    ///
    /// # Errors
    ///
    /// Returns `NumberError` if the string cannot be parsed as a valid number.
    /// This includes invalid number formats, out-of-range values, and malformed
    /// hexadecimal literals.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gene::values::Number;
    ///
    /// let n1 = Number::parse("42").unwrap();
    /// assert!(matches!(n1, Number::Uint(_)));
    ///
    /// let n2 = Number::parse("-5").unwrap();
    /// assert!(matches!(n2, Number::Int(_)));
    ///
    /// let n3 = Number::parse("3.14").unwrap();
    /// assert!(matches!(n3, Number::Float(_)));
    ///
    /// let n4 = Number::parse("0x1F").unwrap();
    /// assert!(matches!(n4, Number::Uint(_)));
    /// ```
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

    /// Returns `true` if this number is an unsigned integer.
    ///
    /// This method checks if the number is stored in the `Uint(u64)` variant.
    /// Unsigned integers are used for non-negative values that fit within the
    /// `u64` range.
    #[inline(always)]
    pub fn is_uint(&self) -> bool {
        matches!(self, Self::Uint(_))
    }

    /// Returns `true` if this number is a floating-point value.
    ///
    /// This method checks if the number is stored in the `Float(f64)` variant.
    /// Floating-point numbers are used for values with decimal precision.
    #[inline(always)]
    pub fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// Returns `true` if this number is a signed integer.
    ///
    /// This method checks if the number is stored in the `Int(i64)` variant.
    /// Signed integers are used for negative values or zero. Positive values
    /// that could fit in `u64` are represented as `Uint` variants instead.
    #[inline(always)]
    pub fn is_int(&self) -> bool {
        matches!(self, Self::Int(_))
    }
}

/// A FieldValue is an enum representing the different values
/// a field from a structure can have. Many conversions
/// from base and common types are implemented.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'field> {
    /// A vector of field values.
    Vector(Vec<FieldValue<'field>>),
    /// A string value.
    String(Cow<'field, str>),
    /// A numeric value.
    Number(Number),
    /// A boolean value.
    Bool(bool),
    /// A field that could be anything.
    Some,
    /// A None value from an [`Option<T>`] field.
    None,
}

impl FieldValue<'_> {
    pub(crate) const fn type_str(&self) -> &'static str {
        match self {
            Self::Vector(_) => "vector",
            Self::Bool(_) => "bool",
            Self::String(_) => "string",
            Self::Number(_) => "number",
            Self::Some => "some",
            Self::None => "none",
        }
    }

    pub(crate) fn string_into_number(&self) -> Result<Self, NumberError> {
        match self {
            Self::String(s) => Ok(Self::Number(Number::from_str(s)?)),
            _ => Err(NumberError::Other(String::from(
                "enum variant is not a string",
            ))),
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

    #[cfg(test)]
    #[inline(always)]
    pub(crate) const fn is_vector(&self) -> bool {
        matches!(self, FieldValue::Vector(_))
    }
}

macro_rules! impl_field_value_number {
    ($($src:ty),*) => {
        $(
        impl From<$src> for FieldValue<'_> {
            fn from(value: $src) -> Self {
                Self::Number(value.into())
            }
        }

        impl From<&$src> for FieldValue<'_> {
            fn from(value: &$src) -> Self {
                Self::Number((*value).into())
            }
        }
        )*
    };
}

impl_field_value_number!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, f32, f64);

impl<'s> From<Cow<'s, str>> for FieldValue<'s> {
    fn from(value: Cow<'s, str>) -> Self {
        Self::String(value)
    }
}

impl<'s> From<&'s Cow<'s, str>> for FieldValue<'s> {
    fn from(value: &'s Cow<'s, str>) -> Self {
        Self::String(value.as_ref().into())
    }
}

impl<'s> From<Cow<'s, PathBuf>> for FieldValue<'s> {
    fn from(value: Cow<'s, PathBuf>) -> Self {
        value.to_string_lossy().to_string().into()
    }
}

impl<'s> From<&'s Cow<'s, PathBuf>> for FieldValue<'s> {
    fn from(value: &'s Cow<'s, PathBuf>) -> Self {
        value.to_string_lossy().into()
    }
}

impl<'s> From<&'s str> for FieldValue<'s> {
    fn from(value: &'s str) -> Self {
        Self::String(Cow::Borrowed(value))
    }
}

impl<'s> From<&&'s str> for FieldValue<'s> {
    fn from(value: &&'s str) -> Self {
        Self::String(Cow::Borrowed(value))
    }
}

impl From<String> for FieldValue<'_> {
    fn from(value: String) -> Self {
        Self::String(Cow::from(value))
    }
}

impl<'s> From<&'s String> for FieldValue<'s> {
    fn from(value: &'s String) -> Self {
        Self::String(Cow::from(value))
    }
}

impl From<PathBuf> for FieldValue<'_> {
    fn from(value: PathBuf) -> Self {
        value.to_string_lossy().to_string().into()
    }
}

impl<'f> From<&'f PathBuf> for FieldValue<'f> {
    fn from(value: &'f PathBuf) -> Self {
        value.to_string_lossy().into()
    }
}

impl From<bool> for FieldValue<'_> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&bool> for FieldValue<'_> {
    fn from(value: &bool) -> Self {
        Self::Bool(*value)
    }
}

impl<'s, T> From<Option<T>> for FieldValue<'s>
where
    T: Into<FieldValue<'s>>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(b) => b.into(),
            None => Self::None,
        }
    }
}

impl<'s, T> From<&'s Option<T>> for FieldValue<'s>
where
    T: Into<FieldValue<'s>> + Clone,
    FieldValue<'s>: std::convert::From<&'s T>,
{
    fn from(value: &'s Option<T>) -> Self {
        match value {
            Some(b) => b.into(),
            None => Self::None,
        }
    }
}

macro_rules! impl_field_value_vec_conversions {
    ($($ty:ty),*) => {
        $(
            impl<'s> From<&'s [$ty]> for FieldValue<'s> {
                fn from(value: &'s [$ty]) -> Self {
                    Self::Vector(value.iter().map(|t| t.into()).collect())
                }
            }

            impl<'s> From<&'s Vec<$ty>> for FieldValue<'s> {
                fn from(value: &'s Vec<$ty>) -> Self {
                    value.as_slice().into()
                }
            }

            impl<'s> From<Vec<$ty>> for FieldValue<'s> {
                fn from(value: Vec<$ty>) -> Self {
                    Self::Vector(value.into_iter().map(|t| t.into()).collect())
                }
            }
        )*
    };
}

// Apply the macro for common types
impl_field_value_vec_conversions!(
    String,
    &'s str,
    Cow<'s, str>,
    PathBuf,
    i8,
    i16,
    i32,
    i64,
    isize,
    u8,
    u16,
    u32,
    u64,
    usize,
    f32,
    f64,
    bool
);

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
            FieldValue::String("42.0".into())
                .string_into_number()
                .unwrap(),
            FieldValue::Number(42.0.into())
        );

        assert_eq!(
            FieldValue::String("-0.42".into())
                .string_into_number()
                .unwrap(),
            FieldValue::Number(Number::from(-0.42))
        );

        assert_eq!(
            FieldValue::String("-42".into())
                .string_into_number()
                .unwrap(),
            FieldValue::Number(Number::from(-42))
        );
    }
}
