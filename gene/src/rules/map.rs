use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    fmt,
    ops::{Deref, DerefMut},
};

#[derive(Debug, Clone, Serialize)]
pub struct MatchHashMap<K, V>(HashMap<K, V>);

impl<K, V> Deref for MatchHashMap<K, V> {
    type Target = HashMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for MatchHashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de, K, V> Deserialize<'de> for MatchHashMap<K, V>
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
            type Value = MatchHashMap<K, V>;

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

                Ok(MatchHashMap(values))
            }
        }

        deserializer.deserialize_map(MatchMapVisitor(std::marker::PhantomData))
    }
}
