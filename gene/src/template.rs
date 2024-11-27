use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use crate::{map::UKHashMap, Rule};

#[derive(Debug, Error)]
pub enum Error {
    #[error("duplicate template name: {0}")]
    Duplicate(String),
}

/// Structure holding string templates to replace in rules. Templating
/// mechanism allow to define once complex regex and use them at multiple
/// places in rules, making rule maintenance easier.
///
/// # Example
///
/// ```
/// use gene::Compiler;
///
/// let mut c = Compiler::new();
///         
/// /// loading template from string
/// c.load_templates_from_str(
///     r#"
/// some_template: hello world
/// "#,
/// )
/// .unwrap();
///
/// c.load_rules_from_str(
///     r#"
/// name: test
/// matches:
///     $m: .data.path == '{{some_template}}'
/// "#,
/// ).unwrap();
///
/// /// we verify our template has been replaced
/// assert_eq!(
///     c.rules()
///         .unwrap()
///         .first()
///         .unwrap()
///         .matches
///         .as_ref()
///         .unwrap()
///         .get("$m")
///         .unwrap(),
///     &String::from(".data.path == 'hello world'")
/// );
/// ```
#[derive(Default, Debug, Deserialize, Clone)]
pub struct Templates(UKHashMap<String, String>);

impl From<HashMap<String, String>> for Templates {
    fn from(value: HashMap<String, String>) -> Self {
        Self(value.into())
    }
}

impl Templates {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new string template. Under the `matches` section of a [Rule]
    /// any occurrence of `{{name}}` (`name` being the template name) will be
    /// replaced by the `template`.
    #[inline]
    pub fn insert(&mut self, name: String, template: String) -> Result<(), Error> {
        if self.0.contains_key(&name) {
            return Err(Error::Duplicate(name));
        }
        self.0.insert(name, template);
        Ok(())
    }

    /// Extends templates from another
    #[inline]
    pub fn extend(&mut self, o: &Self) -> Result<(), Error> {
        for (name, template) in o.0.iter() {
            self.insert(name.clone(), template.clone())?;
        }
        Ok(())
    }

    /// Replaces templates in the given [Rule]
    pub fn replace(&self, r: &mut Rule) {
        if let Some(matches) = r.matches.as_mut() {
            for op in matches.keys().cloned().collect::<Vec<_>>() {
                matches.entry(op.clone()).and_modify(|s| {
                    let mut new = s.clone();
                    self.0
                        .iter()
                        .for_each(|(name, tpl)| new = new.replace(&format!("{{{{{name}}}}}"), tpl));
                    *s = new;
                });
            }
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
