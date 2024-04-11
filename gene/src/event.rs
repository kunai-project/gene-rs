use std::{
    borrow::Cow,
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{FieldValue, XPath};

/// Trait representing a log event
pub trait Event: FieldGetter {
    fn id(&self) -> i64;
    fn source(&self) -> Cow<'_, str>;
}

/// Trait representing a structure we can fetch field values
/// from a [XPath]
pub trait FieldGetter {
    #[inline]
    fn get_from_path(&self, path: &XPath) -> Option<FieldValue> {
        self.get_from_iter(path.iter_segments())
    }

    fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue>;
}

macro_rules! impl_with_getter {
    ($(($type:ty, $getter:tt)),*) => {
        $(
            impl FieldGetter for $type {
                #[inline]
                fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
                    if i.len() > 0 {
                        return None;
                    }
                    Some(self.$getter().into())
                }
            }
        )*
    };
}

macro_rules! impl_for_type {
    ($($type: ty),*) => {
        $(
            impl FieldGetter for $type {
                #[inline]
                fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
                    if i.len() > 0 {
                        return None;
                    }
                    Some(self.clone().into())
                }
            }
        )*
    };
}

impl_for_type!(
    Cow<'_, str>,
    &str,
    String,
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

impl_with_getter!(
    (Path, to_string_lossy),
    (PathBuf, to_string_lossy),
    (IpAddr, to_string)
);

impl<T> FieldGetter for Option<T>
where
    T: FieldGetter,
{
    #[inline]
    fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
        match self {
            Some(v) => v.get_from_iter(i),
            None => None,
        }
    }
}

impl<T> FieldGetter for HashMap<String, T>
where
    T: Into<FieldValue> + Clone,
{
    #[inline]
    fn get_from_iter(
        &self,
        mut i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<FieldValue> {
        let k = i.next()?;
        if i.len() > 0 {
            return None;
        }
        self.get(k).cloned().map(|f| f.into())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use gene_derive::{Event, FieldGetter};
    use serde::Deserialize;

    use super::*;

    macro_rules! path {
        ($p:literal) => {
            XPath::from_str($p).unwrap()
        };
    }

    #[derive(FieldGetter, Deserialize, Default)]
    #[getter(use_serde_rename)]
    struct LogData {
        some_float: f32,
        #[serde(rename = "serde_renamed")]
        some_string: &'static str,
        #[getter(rename = "event_id")]
        id: i64,
        #[getter(skip)]
        #[allow(dead_code)]
        osef: u32,
        path: PathBuf,
    }

    // this is just a show case, it would be
    // shorter to set source = "test".into()
    #[inline]
    fn source() -> Cow<'static, str> {
        "test".into()
    }

    #[derive(Event, FieldGetter, Default)]
    #[event(id = self.data.id, source = source())]
    struct LogEntry<T>
    where
        T: Default,
    {
        name: String,
        data: LogData,
        t: T,
    }

    #[test]
    fn test_derive_event() {
        let entry = LogEntry::<i64> {
            name: "SomeLogEntry".into(),
            data: LogData {
                some_float: 4242.0,
                some_string: "some &'static str",
                id: 42,
                osef: 34,
                path: PathBuf::from("/absolute/path"),
            },
            t: 24,
        };

        assert_eq!(
            entry.get_from_path(&path!(".name")),
            Some("SomeLogEntry".into())
        );
        assert_eq!(
            entry.get_from_path(&path!(".data.some_float")),
            Some(4242.0.into())
        );

        // test that event id is generated correctly
        assert_eq!(entry.id(), 42);

        // check that #[event(rename)] worked
        assert_eq!(
            entry.get_from_path(&path!(".data.event_id")),
            Some(42i64.into())
        );
        // even if renamed we should still be able to reach via the real field name
        assert_eq!(entry.get_from_path(&path!(".data.id")), Some(42i64.into()));

        // check that #[serde(rename)] worked
        assert_eq!(
            entry.get_from_path(&path!(".data.serde_renamed")),
            Some("some &'static str".into())
        );

        // check that #[event(skip)] worked
        assert_eq!(entry.get_from_path(&path!(".data.osef")), None,);

        assert_eq!(entry.get_from_path(&path!(".t")), Some(24.into()));

        // getting a PathBuf must return a FieldValue::String
        assert_eq!(
            entry.get_from_path(&path!(".data.path")),
            Some("/absolute/path".into())
        );

        // checking that source function got generated properly
        assert_eq!(entry.source(), "test");
    }

    #[test]
    // test reproducing https://github.com/0xrawsec/gene-rs/issues/1
    fn test_option_bug() {
        #[derive(FieldGetter, Debug)]
        pub struct SomeStruct {
            some_value: u64,
        }

        #[derive(Event, FieldGetter, Debug)]
        #[event(id = 1, source = "whatever".into())]
        pub struct SomeEvent {
            pub type_id: String,
            pub data: Option<SomeStruct>,
        }

        let event = SomeEvent {
            type_id: "some_id".to_string(),
            data: Some(SomeStruct { some_value: 1 }),
        };

        assert_eq!(
            event.get_from_path(&path!(".type_id")),
            Some("some_id".into())
        );

        assert!(event.get_from_path(&path!(".data")).is_none());
        assert_eq!(
            event.get_from_path(&path!(".data.some_value")),
            Some(1u64.into())
        );
    }
}
