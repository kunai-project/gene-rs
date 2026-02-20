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
    /// Creates a new, empty template collection.
    ///
    /// Returns a `Templates` instance with no template variables defined.
    /// This is equivalent to calling `Templates::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new template variable into this collection.
    ///
    /// Adds a name-template pair that can be used for substitution in rule match
    /// expressions. Template placeholders in the format `{{name}}` will be replaced
    /// with the provided template value when the rule is processed.
    ///
    /// # Errors
    ///
    /// Returns `Error::Duplicate` if a template with the same name already exists
    /// in this collection. This prevents accidental overwrites of existing templates.
    #[inline]
    pub fn insert(&mut self, name: String, template: String) -> Result<(), Error> {
        if self.0.contains_key(&name) {
            return Err(Error::Duplicate(name));
        }
        self.0.insert(name, template);
        Ok(())
    }

    /// Extends this template collection with templates from another collection.
    ///
    /// Merges all templates from the provided collection into this one. If any
    /// template names conflict, an error is returned and no templates are added.
    ///
    /// This method is useful for composing template collections from multiple
    /// sources or applying base templates with overrides.
    ///
    /// # Errors
    ///
    /// Returns `Error::Duplicate` if any template name in the source collection
    /// already exists in this collection. The operation is atomic - if any
    /// duplicate is found, no templates are added.
    #[inline]
    pub fn extend(&mut self, o: &Self) -> Result<(), Error> {
        for (name, template) in o.0.iter() {
            self.insert(name.clone(), template.clone())?;
        }
        Ok(())
    }

    /// Replaces template placeholders in a rule's match expressions.
    ///
    /// Iterates through all match expressions in the rule and replaces any template
    /// placeholders (in the format `{{name}}`) with their corresponding values from
    /// this collection. This allows for dynamic rule configuration through templates.
    ///
    /// # Behavior
    ///
    /// - Only affects the `matches` section of the rule
    /// - Placeholders are replaced in-place in the match expressions
    /// - If a template name is not found, the placeholder remains unchanged
    /// - Multiple occurrences of the same template are all replaced
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gene::Templates;
    /// use gene::rules::Rule;
    ///
    /// let mut rule: Rule = serde_yaml::from_str(
    ///     "name: test\nmatches:\n  $a: .path == \"{{path}}\"\ncondition: $a"
    /// ).unwrap();
    ///
    /// let mut templates = Templates::new();
    /// templates.insert("path".to_string(), "/var/log/".to_string()).unwrap();
    ///
    /// templates.replace(&mut rule);
    /// // rule.matches now contains ".path == \"/var/log/\""
    /// ```
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

    /// Returns the number of template variables in this collection.
    ///
    /// This method returns the count of key-value pairs stored in the templates.
    /// It provides a way to determine how many template variables are available
    /// for substitution in rules.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this collection contains no template variables.
    ///
    /// This is a convenience method that checks if the number of templates is zero.
    /// It's equivalent to `self.len() == 0` but may be more readable in some contexts.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
