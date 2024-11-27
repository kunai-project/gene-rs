use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    fmt,
    ops::{Deref, DerefMut},
};

/// HashMap implementation providing key uniqueness at Deserialization
#[derive(Default, Debug, Clone, Serialize)]
pub(crate) struct UKHashMap<K, V>(HashMap<K, V>);

impl<K, V> From<UKHashMap<K, V>> for HashMap<K, V> {
    fn from(value: UKHashMap<K, V>) -> Self {
        value.0
    }
}

impl<K, V> From<HashMap<K, V>> for UKHashMap<K, V> {
    fn from(value: HashMap<K, V>) -> Self {
        Self(value)
    }
}

impl<K, V> Deref for UKHashMap<K, V> {
    type Target = HashMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for UKHashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// helper to deserialize a UKHashMap into a HashMap
#[inline(always)]
pub(crate) fn deserialize_uk_hashmap<'de, D, K, V>(
    deserializer: D,
) -> Result<Option<HashMap<K, V>>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Eq + std::hash::Hash + fmt::Debug,
    V: Deserialize<'de>,
{
    let s = Option::<UKHashMap<K, V>>::deserialize(deserializer)?;
    Ok(s.map(|m| m.into()))
}

impl<'de, K, V> Deserialize<'de> for UKHashMap<K, V>
where
    K: Deserialize<'de> + Eq + std::hash::Hash + fmt::Debug,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MatchMapVisitor<K, V>(std::marker::PhantomData<(K, V)>);

        impl<'de, K, V> de::Visitor<'de> for MatchMapVisitor<K, V>
        where
            K: Deserialize<'de> + Eq + std::hash::Hash + fmt::Debug,
            V: Deserialize<'de>,
        {
            type Value = UKHashMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with unique keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut values = HashMap::new();

                while let Some((key, value)) = map.next_entry()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate key found: {:?}", key)));
                    }
                    values.insert(key, value);
                }

                Ok(UKHashMap(values))
            }
        }

        deserializer.deserialize_map(MatchMapVisitor(std::marker::PhantomData))
    }
}
