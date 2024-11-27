use std::{
    collections::{HashMap, HashSet},
    io,
};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    rules::{self, CompiledRule},
    template, Rule, Templates,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("duplicate rule={0}")]
    DuplicateRule(String),
    #[error("unknown rule dependency in rule={0}")]
    UnknownRuleDependency(String),
    #[error("rule error: {0}")]
    Rule(#[from] rules::Error),
    #[error("template: error {0}")]
    Template(#[from] template::Error),
    #[error("yaml error: {0}")]
    Serde(#[from] serde_yaml::Error),
}

/// Rule compiler
#[derive(Default, Clone)]
pub struct Compiler {
    templates: Templates,
    names: HashMap<String, usize>,
    loaded: HashSet<String>,
    rules: Vec<Rule>,
    pub(crate) compiled: Vec<CompiledRule>,
}

impl Compiler {
    /// Creates a new `Compiler`
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads templates from a reader implementing [io::Read] trait. The data within the
    /// reader must a `HashMap<String, String>` YAML formatted.
    #[inline]
    pub fn load_templates_from_reader<R: io::Read>(&mut self, r: R) -> Result<(), Error> {
        for document in serde_yaml::Deserializer::from_reader(r) {
            self.load_templates(Templates::deserialize(document)?)?;
        }
        Ok(())
    }

    /// Wrapper around [Compiler::load_templates_from_reader] loading a rules
    /// from a struct implementing [AsRef<str>]
    pub fn load_templates_from_str<S: AsRef<str>>(&mut self, s: S) -> Result<(), Error> {
        let c = io::Cursor::new(s.as_ref());
        self.load_templates_from_reader(c)
    }

    /// Loads a set of string [Templates] into the compiler so that it
    /// can replace the appropriate strings into the rules before compiling them
    pub fn load_templates(&mut self, t: Templates) -> Result<(), Error> {
        self.templates.extend(&t)?;
        Ok(())
    }

    /// Load a rule from a reader implementing [io::Read] trait. The data must be formatted
    /// in YAML following the YAML documents format otherwise this function will fail.
    #[inline]
    pub fn load_rules_from_reader<R: io::Read>(&mut self, r: R) -> Result<(), Error> {
        for document in serde_yaml::Deserializer::from_reader(r) {
            self.load(Rule::deserialize(document)?)?;
        }
        Ok(())
    }

    /// Wrapper around [Compiler::load_rules_from_reader] loading a rules
    /// from a struct implementing [AsRef<str>]
    pub fn load_rules_from_str<S: AsRef<str>>(&mut self, s: S) -> Result<(), Error> {
        let c = io::Cursor::new(s.as_ref());
        self.load_rules_from_reader(c)
    }

    /// Load a rule into the `Compiler`.
    #[inline]
    pub fn load(&mut self, mut r: Rule) -> Result<(), Error> {
        if r.is_disabled() {
            return Ok(());
        }

        if self.loaded.contains(&r.name) {
            return Err(Error::DuplicateRule(r.name));
        }

        // we replace template strings used in rule
        self.templates.replace(&mut r);

        self.loaded.insert(r.name.clone());

        self.rules.push(r);

        Ok(())
    }

    /// Compile all the [Rule] loaded via [Compiler::load] which
    /// have not been compiled yet.
    #[inline]
    pub fn compile(&mut self) -> Result<(), Error> {
        // no need to do the job again
        if self.is_ready() {
            return Ok(());
        }

        // we must compile in the order of insertion to check
        // for dependencies
        for (i, r) in self.rules.iter().enumerate() {
            // we do not re-compile rules already compiled
            if self.names.contains_key(&r.name) {
                continue;
            }

            let compiled: CompiledRule = r.clone().try_into()?;

            // We verify that all rules we depend on are known.
            // The fact that rule dependencies must be known makes
            // circular references impossible
            for dep in compiled.depends.iter() {
                self.names
                    .get(dep)
                    .ok_or(Error::UnknownRuleDependency(dep.clone()))?;
            }

            // we need to be sure nothing can fail beyond this point not
            // to create inconsistencies in compiled and sources members

            // this is the index the rule is going to be inserted at
            self.names.insert(compiled.name.clone(), i);
            self.compiled.push(compiled);
        }

        Ok(())
    }

    /// Returns whether compiler is ready (i.e. all the rules have been compiled)
    #[inline(always)]
    fn is_ready(&self) -> bool {
        self.rules.len() == self.compiled.len()
    }

    /// Retrieves the rules loaded in the compiler after all of them have been checked
    /// against potential compilation errors.
    pub fn rules(&mut self) -> Result<&Vec<Rule>, Error> {
        // we need to re-compile rules as some are missing
        if !self.is_ready() {
            self.compile()?;
        }
        Ok(&self.rules)
    }

    /// Retrieves all compiled rules
    pub fn compiled(&mut self) -> Result<&Vec<CompiledRule>, Error> {
        // we need to re-compile rules as some are missing
        if !self.is_ready() {
            self.compile()?;
        }
        Ok(&self.compiled)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_load_from_str() {
        let mut c = Compiler::new();

        c.load_rules_from_str(
            r#"
name: test
"#,
        )
        .unwrap();

        assert_eq!(c.rules.len(), 1);
    }

    #[test]
    fn test_load_duplicate_rule() {
        let mut c = Compiler::new();

        let res = c.load_rules_from_str(
            r#"
---
name: test

---
name: test
"#,
        );

        assert!(matches!(res, Err(Error::DuplicateRule(_))));
    }

    #[test]
    fn test_load_rule_unk_dep() {
        let mut c = Compiler::new();

        c.load_rules_from_str(
            r#"
name: test
matches:
    $d: rule(unknown.dep)
condition: any of them
"#,
        )
        .unwrap();

        // Unknown RuleDependency is checked at compile time
        assert!(matches!(c.compile(), Err(Error::UnknownRuleDependency(_))));
    }

    #[test]
    fn test_load_templates() {
        let mut c = Compiler::new();

        c.load_templates_from_str(
            r#"
crazy_re: '(this|is|some|re|template)'
str_template: hello world template
"#,
        )
        .unwrap();

        assert_eq!(c.templates.len(), 2)
    }

    #[test]
    fn test_load_dup_templates() {
        let mut c = Compiler::new();

        let res = c.load_templates_from_str(
            r#"
str_template: hello world template
str_template: duplicate
"#,
        );

        // when the duplicate is within the same file this is going
        // to be an error raised by the deserialize that doesn't allow it
        assert!(matches!(res, Err(Error::Serde(_))));

        let res = c.load_templates_from_str(
            r#"
str_template: hello world template
---
str_template: duplicate
"#,
        );

        // when the duplicate is in different yaml documents it
        // should raise a template error
        assert!(matches!(res, Err(Error::Template(_))));
    }

    #[test]
    fn test_templated_rule() {
        let mut c = Compiler::new();

        c.load_templates_from_str(
            r#"
tpl_string: hello world template
"#,
        )
        .unwrap();

        c.load_rules_from_str(
            r#"
name: test
matches:
    $m: .data.path == '{{tpl_string}}'
"#,
        )
        .unwrap();

        assert_eq!(
            c.rules()
                .unwrap()
                .first()
                .unwrap()
                .matches
                .as_ref()
                .unwrap()
                .get("$m")
                .unwrap(),
            &String::from(".data.path == 'hello world template'")
        );
    }

    #[test]
    fn test_rules_order() {
        let mut c = Compiler::new();

        for i in 0..1000 {
            c.load_rules_from_str(format!("name: rule.{i}")).unwrap()
        }

        c.compile().unwrap();

        for i in 0..1000 {
            assert_eq!(c.rules[i].name, c.compiled[i].name);
        }
    }
}
