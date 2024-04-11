use core::hash::Hash;
use std::{borrow::Cow, str::FromStr};

use thiserror::Error;

use crate::rules::matcher::{MatchParser, Rule};

#[derive(Error, Debug, Clone)]
pub enum PathError {
    #[error("{0}")]
    Parse(#[from] Box<pest::error::Error<Rule>>),
}

/// Cross Path allowing to recursively retrieve a [FieldValue](crate::FieldValue)
/// from a structure implementing [FieldGetter](crate::FieldGetter).
///
/// # Example:
///
/// ```rust
/// use ::gene_derive::FieldGetter;
/// use ::gene::{XPath, FieldGetter, FieldValue};
///
/// #[derive(FieldGetter)]
/// struct LogData
/// {
///     a: String,
///     b: i32,
///     c: f64,
/// }
///
/// #[derive(FieldGetter)]
/// struct LogEntry
/// {
///     name: String,
///     data: LogData,
/// }
///
/// let e = LogEntry{
///     name: "SomeEntry".into(),
///     data: LogData{
///         a: "SomeData".into(),
///         b: 42,
///         c: 24.0,
///     }
/// };
///
/// let p = XPath::parse(".name").unwrap();
/// assert_eq!(e.get_from_path(&p), Some("SomeEntry".into()));
///
/// let p = XPath::parse(".data.a").unwrap();
/// assert_eq!(e.get_from_path(&p), Some("SomeData".into()));
///
/// let p = XPath::parse(".data.b").unwrap();
/// assert_eq!(e.get_from_path(&p), Some(42.into()));
///
/// let p = XPath::parse(".data.c").unwrap();
/// assert_eq!(e.get_from_path(&p), Some(24.0.into()));
/// ```
#[derive(Clone, Debug, Eq)]
pub struct XPath {
    path: String,
    segments: Vec<String>,
}

impl Hash for XPath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state)
    }
}

impl FromStr for XPath {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl PartialEq for XPath {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        if self.path.len() != other.path.len() {
            return false;
        }

        let mut o = other.path.as_bytes().iter().rev();
        for b in self.path.as_bytes().iter().rev() {
            if Some(b) != o.next() {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for XPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

impl XPath {
    /// builds an `XPath` from a [str]
    #[inline]
    pub fn parse<S: AsRef<str>>(s: S) -> Result<Self, PathError> {
        Ok(XPath {
            path: String::from(s.as_ref()),
            segments: MatchParser::parse_path(s)?,
        })
    }

    /// getter to the segments of the path. If a path has been
    /// built from `.a.b.c` the segments will be `["a", "b", "c"]` as `.` is the
    /// path segments separator
    #[inline(always)]
    pub fn segments(&self) -> &Vec<String> {
        &self.segments
    }

    /// provides an iterator over the segments of the path
    #[inline(always)]
    pub fn iter_segments(&self) -> core::slice::Iter<'_, std::string::String> {
        self.segments.iter()
    }

    #[inline(always)]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        Cow::from(&self.path)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::XPath;

    #[test]
    fn test_path() {
        let s = r#".data.exe.file."with space"."with .""#;
        let p = XPath::from_str(s).unwrap();
        assert_eq!(p.to_string_lossy(), s);
        assert_eq!(p.segments[0], "data");
        assert_eq!(p.segments[1], "exe");
        assert_eq!(p.segments[2], "file");
        assert_eq!(p.segments[3], "with space");
        assert_eq!(p.segments[4], "with .");
        assert_eq!(p, XPath::from_str(s).unwrap());

        let mut i = p.iter_segments();
        assert_eq!(i.next(), Some(&"data".into()));
        assert_eq!(i.next(), Some(&"exe".into()));
        assert_eq!(i.next(), Some(&"file".into()));
        assert_eq!(i.next(), Some(&"with space".into()));
        assert_eq!(i.next(), Some(&"with .".into()));
    }
}
