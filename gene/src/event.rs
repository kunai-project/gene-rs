use std::{
    borrow::Cow,
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{FieldValue, XPath};

/// Trait representing a log event
pub trait Event<'event>: FieldGetter<'event> {
    fn id(&self) -> i64;
    fn source(&self) -> Cow<'_, str>;
}

/// Trait representing a structure we can fetch field values
/// from a [`XPath`]
pub trait FieldGetter<'field> {
    #[inline]
    fn get_from_path(&'field self, path: &XPath) -> Option<FieldValue<'field>> {
        self.get_from_iter(path.iter_segments())
    }

    fn get_from_iter(
        &'field self,
        i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<FieldValue<'field>>;
}

macro_rules! impl_with_getter {
    ($(($type:ty, $getter:tt)),*) => {
        $(
            impl<'f> FieldGetter<'f> for $type {
                #[inline]
                fn get_from_iter(&'f self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue<'f>> {
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
            impl<'f> FieldGetter<'f>  for $type {
                #[inline]
                fn get_from_iter(&'f self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue<'f>> {
                    if i.len() > 0 {
                        return None;
                    }
                    Some(self.into())
                }
            }
        )*
    };
}

impl_for_type!(
    Cow<'_, str>,
    Cow<'_, PathBuf>,
    &'_ str,
    str,
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

impl<'field, T> FieldGetter<'field> for Option<T>
where
    T: FieldGetter<'field>,
{
    #[inline]
    fn get_from_iter(
        &'field self,
        i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<FieldValue<'field>> {
        match self {
            Some(v) => v.get_from_iter(i),
            None => Some(FieldValue::None),
        }
    }
}

impl<'f, T> FieldGetter<'f> for HashMap<String, T>
where
    T: FieldGetter<'f>,
{
    #[inline]
    fn get_from_iter(
        &'f self,
        mut i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<FieldValue<'f>> {
        let k = match i.next() {
            Some(s) => s,
            None => {
                // No key to look up, return Some to indicate map existence
                return Some(FieldValue::Some);
            }
        };

        self.get(k)?.get_from_iter(i)
    }
}

macro_rules! impl_field_getter_for_vec {
    ($($ty:ty),*) => {
        $(
            impl<'f> FieldGetter<'f> for Vec<$ty>
            where
                $ty: Into<FieldValue<'f>>,
            {
                #[inline]
                fn get_from_iter(
                    &'f self,
                    i: core::slice::Iter<'_, std::string::String>,
                ) -> Option<FieldValue<'f>> {
                    if i.len() > 0 {
                        return None;
                    }

                    Some(FieldValue::Vector(self.iter().map(|v| v.into()).collect()))
                }
            }
        )*
    };
}

// Apply the macro for common types
impl_field_getter_for_vec!(
    String,
    Cow<'f, str>,
    Cow<'f, PathBuf>,
    &'f str,
    i8,
    i16,
    i32,
    i64,
    u8,
    u16,
    u32,
    u64,
    f32,
    f64,
    bool
);

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
        some_string: String,
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
                some_string: "some string".into(),
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
            Some("some string".into())
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

        assert_eq!(
            event.get_from_path(&path!(".data.some_value")),
            Some(1u64.into())
        );

        // if value is not known, it must at least return FieldValue::Some
        assert!(event.get_from_path(&path!(".data")).is_some());
        // None must be returned if trying to get a non existing field
        assert!(event.get_from_path(&path!(".unknown")).is_none());
    }

    #[test]
    fn test_vec_field_getter() {
        // Test in a struct context
        #[derive(FieldGetter)]
        struct TestStruct {
            items: Vec<String>,
            numbers: Vec<i32>,
        }

        let test_struct = TestStruct {
            items: vec!["first".into(), "second".into()],
            numbers: vec![10, 20, 30],
        };

        // Test accessing vec fields directly
        assert!(test_struct
            .get_from_path(&path!(".items"))
            .unwrap()
            .is_vector());

        assert!(test_struct
            .get_from_path(&path!(".numbers"))
            .unwrap()
            .is_vector());

        // Test that nested access returns None (as expected by the implementation)
        assert!(test_struct.get_from_path(&path!(".items.0")).is_none());
        assert!(test_struct
            .get_from_path(&path!(".numbers.first"))
            .is_none());
    }

    #[test]
    fn test_hashmap_field_getter() {
        use std::collections::HashMap;

        // Test direct HashMap implementation
        let mut map = HashMap::new();
        map.insert("name".to_string(), "test".to_string());

        // Test accessing existing keys
        assert_eq!(map.get_from_path(&path!(".name")), Some("test".into()));

        // Test accessing non-existing keys
        assert_eq!(map.get_from_path(&path!(".unknown")), None);

        // Test that nested access returns None (more than one segment)
        assert_eq!(map.get_from_path(&path!(".name.nested")), None);

        // Test in a struct context
        #[derive(FieldGetter)]
        struct TestStruct {
            data: HashMap<String, String>,
            metadata: HashMap<String, i32>,
        }

        let mut data_map = HashMap::new();
        data_map.insert("key1".to_string(), "value1".to_string());
        data_map.insert("key2".to_string(), "value2".to_string());

        let mut metadata_map = HashMap::new();
        metadata_map.insert("count".to_string(), 100);
        metadata_map.insert("size".to_string(), 200);

        let test_struct = TestStruct {
            data: data_map,
            metadata: metadata_map,
        };

        // Test accessing hashmap fields directly
        assert_eq!(
            test_struct.get_from_path(&path!(".data")),
            Some(FieldValue::Some)
        );
        assert_eq!(
            test_struct.get_from_path(&path!(".metadata")),
            Some(FieldValue::Some)
        );

        // Test accessing nested hashmap values
        assert_eq!(
            test_struct.get_from_path(&path!(".data.key1")),
            Some("value1".into())
        );
        assert_eq!(
            test_struct.get_from_path(&path!(".metadata.count")),
            Some(100i32.into())
        );

        // Test accessing non-existing nested keys
        assert_eq!(test_struct.get_from_path(&path!(".data.unknown")), None);
        assert_eq!(test_struct.get_from_path(&path!(".metadata.missing")), None);
    }
}
