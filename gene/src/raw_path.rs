use std::{
    borrow::Cow,
    ops::Deref,
    path::{Path, PathBuf},
};

use gene_encoding::unescape_invalid_utf8;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::{escape_invalid_utf8, FieldGetter, FieldNameIterator, FieldValue};

/// A file path, seen as text by rules and serializers.
///
/// Rules and [`Serialize`] see the path converted with
/// [`escape_invalid_utf8`](crate::escape_invalid_utf8), so invalid UTF-8
/// bytes appear as `\xNN` instead of being replaced by `U+FFFD`.
/// [`Deserialize`] converts that text back, so a serialized path is read
/// back with its exact bytes. It derefs to [`std::path::Path`] for file
/// operations.
///
/// Outside Unix, deserializing fails when the decoded bytes are not valid
/// UTF-8, as there is no safe way to build such a path there.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RawPath(PathBuf);

impl RawPath {
    fn escaped(&self) -> Cow<'_, str> {
        escape_invalid_utf8(self.0.as_os_str().as_encoded_bytes())
    }
}

impl From<PathBuf> for RawPath {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl Deref for RawPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

#[cfg(unix)]
fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    Some(OsString::from_vec(bytes).into())
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    String::from_utf8(bytes).ok().map(PathBuf::from)
}

impl<'de> Deserialize<'de> for RawPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = unescape_invalid_utf8(&text).into_owned();
        path_from_bytes(bytes)
            .map(Self)
            .ok_or_else(|| D::Error::custom("path is not valid UTF-8 on this platform"))
    }
}

impl Serialize for RawPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.escaped())
    }
}

impl<'f> FieldGetter<'f> for RawPath {
    #[inline]
    fn get_from_iter(&'f self, i: FieldNameIterator<'_>) -> Option<FieldValue<'f>> {
        if !i.is_terminal() {
            return None;
        }
        Some(self.escaped().into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    use gene_derive::FieldGetter;

    use super::*;
    use crate::XPath;

    #[derive(FieldGetter)]
    struct File {
        path: RawPath,
    }

    fn invalid_utf8_path() -> RawPath {
        PathBuf::from(OsString::from_vec(b"/tmp/\xff".to_vec())).into()
    }

    fn get<'f>(file: &'f File, path: &str) -> Option<FieldValue<'f>> {
        file.get_from_path(&XPath::parse(path).unwrap())
    }

    #[test]
    fn test_field_getter_escapes_invalid_utf8() {
        let file = File {
            path: invalid_utf8_path(),
        };
        assert_eq!(get(&file, ".path"), Some("/tmp/\\xff".into()));
    }

    #[test]
    fn test_field_getter_keeps_valid_utf8() {
        let file = File {
            path: PathBuf::from("/tmp/é").into(),
        };
        assert_eq!(get(&file, ".path"), Some("/tmp/é".into()));
    }

    #[test]
    fn test_field_getter_rejects_sub_field() {
        let file = File {
            path: PathBuf::from("/tmp").into(),
        };
        assert_eq!(get(&file, ".path.sub"), None);
    }

    #[test]
    fn test_serialize_escapes_invalid_utf8() {
        assert_eq!(
            serde_json::to_string(&invalid_utf8_path()).unwrap(),
            r#""/tmp/\\xff""#
        );
    }

    #[test]
    fn test_deserialize_restores_raw_bytes() {
        let path: RawPath = serde_json::from_str(r#""/tmp/\\xff""#).unwrap();
        assert_eq!(path, invalid_utf8_path());
    }

    #[test]
    fn test_deserialize_keeps_literal_escape_text() {
        let path: RawPath = serde_json::from_str(r#""/tmp/\\\\xff""#).unwrap();
        assert_eq!(path, PathBuf::from(r"/tmp/\xff").into());
    }

    #[test]
    fn test_serde_round_trip() {
        let paths = [
            invalid_utf8_path(),
            PathBuf::from(r"/tmp/\xff").into(),
            PathBuf::from(r"C:\Windows\System32").into(),
            PathBuf::from("/tmp/é").into(),
        ];
        for path in paths {
            let serialized = serde_json::to_string(&path).unwrap();
            let deserialized: RawPath = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, path);
        }
    }

    #[test]
    fn test_deref_keeps_raw_bytes() {
        assert_eq!(
            invalid_utf8_path().as_os_str().as_encoded_bytes(),
            b"/tmp/\xff"
        );
    }
}
