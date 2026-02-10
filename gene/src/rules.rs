use self::{attack::AttackId, condition::Condition, matcher::Match};
use crate::{map::deserialize_uk_hashmap, template::Templates, Event};

use lazy_static::lazy_static;
use regex::Regex;
use serde::{de, Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io,
    str::FromStr,
};
use thiserror::Error;

// publish modules
mod condition;
// used to parse path
pub(crate) mod matcher;

pub const MAX_SEVERITY: u8 = 10;

pub(crate) fn bound_severity(sev: u8) -> u8 {
    core::cmp::min(sev, MAX_SEVERITY)
}

lazy_static! {
    static ref ATTACK_ID_RE: Regex = Regex::new(r"^[A-Za-z]+[0-9]+(\.[0-9]+)?$").unwrap();
}

mod attack {
    use thiserror::Error;

    use super::ATTACK_ID_RE;

    #[derive(Debug, Error)]
    pub enum Error {
        #[error("invalid attack id: {0}")]
        Invalid(String),
    }

    #[derive(Hash)]
    pub(crate) struct AttackId(String);

    impl AttackId {
        pub(crate) fn parse<S: AsRef<str>>(s: S) -> Result<Self, Error> {
            let s = s.as_ref();
            if !ATTACK_ID_RE.is_match(s) {
                return Err(Error::Invalid(s.into()));
            }
            Ok(Self(s.to_uppercase()))
        }
    }

    impl From<AttackId> for String {
        fn from(value: AttackId) -> Self {
            value.0
        }
    }
}

/// Represents the type of [`Rule`]
#[derive(Debug, Clone, Copy)]
pub enum Type {
    /// Use it to encode detection information.
    /// Rule will be used to update [crate::ScanResult]
    Detection,
    /// Use this type for rules to filter in/out
    /// events. Only `actions` section of the rule will
    /// be used to update [crate::ScanResult].
    Filter,
    /// Use this type if the rule does not aim at being
    /// matched directly but is always used as dependency.
    /// Rule will NEVER be used to update [crate::ScanResult]
    Dependency,
}

impl Type {
    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Filter => "filter",
            Self::Dependency => "dependency",
        }
    }
}

impl Default for Type {
    fn default() -> Self {
        Self::Detection
    }
}

#[derive(Debug, Error, Clone)]
pub enum ParseTypeError {
    #[error("unknown type: {0}")]
    UnkwnownType(String),
}

impl FromStr for Type {
    type Err = ParseTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "detection" => Ok(Self::Detection),
            "filter" => Ok(Self::Filter),
            "dependency" => Ok(Self::Dependency),
            _ => Err(ParseTypeError::UnkwnownType(s.into())),
        }
    }
}

impl Serialize for Type {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

/// Metadata attributes of a rule
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// free text tags associated to the rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashSet<String>>,
    /// [MITRE ATT&CK](https://attack.mitre.org/) ids concerned by this rule
    /// This is not a free-text field, when the rule compiles a format checking
    /// made on the ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<HashSet<String>>,
    /// authors of the rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    /// any comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<Vec<String>>,
}

/// Miscellaneous parameters of the rule
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// whether to disable the rule or not
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
}

/// Defines on which kind of events the rule must match
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchOn {
    /// A map where **keys** are event sources
    /// and **values** are sets of event ids corresponding to that
    /// source. The rule will apply to any event matching
    /// **one** of the source and **one** of its associated event id.
    /// To match all events from a source just leave an empty set of
    /// event ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<HashMap<String, HashSet<i64>>>,
}

/// Structure defining rule loadable in the [`Engine`](crate::Engine)
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// name fo the rule
    pub name: String,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ty: Option<Type>,
    /// rule's metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    /// miscellaneous parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Params>,
    /// match-on directives
    #[serde(rename = "match-on")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_on: Option<MatchOn>,
    /// matches
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_uk_hashmap")]
    pub matches: Option<HashMap<String, String>>,
    /// rule triggering condition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// severity given to the events matching the rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,
    /// actions to take when rule triggers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<HashSet<String>>,
}

impl Rule {
    #[inline]
    pub fn deserialize_reader<R: io::Read>(r: R) -> Vec<Result<Self, serde_yaml::Error>> {
        serde_yaml::Deserializer::from_reader(r)
            .map(Rule::deserialize)
            .collect()
    }

    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        self.params
            .as_ref()
            .and_then(|p| p.disable)
            .unwrap_or_default()
    }

    #[inline]
    pub fn apply_templates(mut self, templates: &Templates) -> Self {
        templates.replace(&mut self);
        self
    }

    // build filter for events to include (positive values in
    // `match-on` section)
    fn build_include_events(
        filters: &HashMap<String, HashSet<i64>>,
    ) -> HashMap<String, HashSet<i64>> {
        let mut inc = HashMap::new();
        for (source, events) in filters {
            let events = events
                .iter()
                .filter(|&&id| id >= 0)
                .cloned()
                .collect::<HashSet<i64>>();
            if !events.is_empty() {
                inc.insert(source.clone(), events);
            }
        }
        inc
    }

    // build filter for events to exclude (negative values in
    // `match-on` section)
    fn build_exclude_events(
        filters: &HashMap<String, HashSet<i64>>,
    ) -> HashMap<String, HashSet<i64>> {
        let mut excl = HashMap::new();
        for (source, events) in filters {
            let events = events
                .iter()
                .filter(|&&id| id < 0)
                .map(|id| id.abs())
                .collect::<HashSet<i64>>();
            if !events.is_empty() {
                excl.insert(source.clone(), events);
            }
        }
        excl
    }

    #[inline]
    pub fn compile_into(self) -> Result<CompiledRule, Error> {
        let name = self.name.clone();
        let filters = self.match_on.and_then(|mo| mo.events).unwrap_or_default();

        // to wrap error with rule name
        || -> Result<CompiledRule, Error> {
            let mut c = CompiledRule {
                name: self.name,
                ty: self.ty.unwrap_or_default(),
                depends: HashSet::new(),
                tags: HashSet::new(),
                attack: HashSet::new(),
                include_events: Self::build_include_events(&filters),
                exclude_events: Self::build_exclude_events(&filters),
                matches: HashMap::new(),
                condition: match self.condition {
                    Some(cond) => {
                        Condition::from_str(&cond).map_err(|e| Error::from(Box::new(e)))?
                    }
                    None => Condition::default(),
                },
                severity: bound_severity(self.severity.unwrap_or_default()),
                actions: self.actions.unwrap_or_default(),
            };

            // populating attack
            if let Some(meta) = self.meta {
                // setting tags
                c.tags = meta.tags.unwrap_or_default();

                // setting attack ids
                if let Some(attack) = meta.attack {
                    // we make sure attack id is correct
                    for r in attack.iter().map(AttackId::parse) {
                        c.attack
                            .insert(r.map_err(|e| Error::Compile(e.to_string()))?.into());
                    }
                }
            }

            // initializing operands
            if let Some(matches) = self.matches {
                for (operand, s) in matches.iter() {
                    if !operand.starts_with('$') {
                        return Err(Error::Compile(format!(
                            "operand must start with $, try with ${operand}"
                        )));
                    }
                    let m = Match::from_str(s)?;
                    // we update the list of dependent rules
                    if let Match::Rule(r) = &m {
                        c.depends.insert(r.rule_name().into());
                    }
                    c.matches.insert(operand.clone(), m);
                }
            }

            Ok(c)
        }()
        .map_err(|e| e.wrap(name))
    }
}

impl FromStr for Rule {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

#[derive(Debug, Default, Clone)]
pub struct CompiledRule {
    pub(crate) name: String,
    pub(crate) ty: Type,
    pub(crate) depends: HashSet<String>,
    pub(crate) tags: HashSet<String>,
    pub(crate) attack: HashSet<String>,
    pub(crate) include_events: HashMap<String, HashSet<i64>>,
    pub(crate) exclude_events: HashMap<String, HashSet<i64>>,
    pub(crate) matches: HashMap<String, Match>,
    pub(crate) condition: condition::Condition,
    pub(crate) severity: u8,
    pub(crate) actions: HashSet<String>,
}

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("rule={0} {1}")]
    Wrap(String, Box<Error>),
    #[error("compile error: {0}")]
    Compile(String),
    #[error("{0}")]
    ParseMatch(#[from] matcher::Error),
    #[error("{0}")]
    Condition(#[from] Box<condition::Error>),
}

impl Error {
    fn wrap(self, name: String) -> Self {
        Self::Wrap(name, Box::new(self))
    }

    pub fn wrapped(&self) -> &Self {
        match self {
            Self::Wrap(_, e) => e,
            _ => self,
        }
    }
}

impl TryFrom<Rule> for CompiledRule {
    type Error = Error;
    fn try_from(r: Rule) -> Result<Self, Self::Error> {
        r.compile_into()
    }
}

impl CompiledRule {
    // keep this function not to break tests
    #[allow(dead_code)]
    #[inline(always)]
    fn match_event<E>(&self, event: &E) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        self.condition
            .compute_for_event(event, &self.matches, &HashMap::new())
            .map_err(|e| Box::new(e).into())
            .map_err(|e: Error| e.wrap(self.name.clone()))
    }

    #[inline(always)]
    pub(crate) fn match_event_with_states<E>(
        &self,
        event: &E,
        rules_states: &HashMap<Cow<'_, str>, bool>,
    ) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        self.condition
            .compute_for_event(event, &self.matches, rules_states)
            .map_err(|e| Box::new(e).into())
            .map_err(|e: Error| e.wrap(self.name.clone()))
    }

    #[inline(always)]
    pub(crate) fn can_match_on<S: AsRef<str>>(&self, src: S, id: i64) -> bool {
        // we have no filter at all
        if self.include_events.is_empty() && self.exclude_events.is_empty() {
            return true;
        }

        // explicit event excluding logic
        let opt_exclude = self.exclude_events.get(src.as_ref());
        if let Some(exclude) = opt_exclude {
            // we definitely want to exclude that event
            if exclude.contains(&id) {
                return false;
            }
        }

        let opt_include = self.include_events.get(src.as_ref());
        // we include if we have no include filter for this source
        // but we have an exclude filter (that didn't match)
        if opt_include.is_none() && opt_exclude.is_some() {
            return true;
        }

        // we return result of lookup in include filter if there is one
        if let Some(include) = opt_include {
            return include.contains(&id);
        }

        // default we cannot match on event
        false
    }

    /// Gives a read only access to the rule's name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gives a read only access to the rule's severity
    pub fn severity(&self) -> u8 {
        self.severity
    }

    /// Returns true if the rule is [Type::Filter]
    #[inline(always)]
    pub fn is_filter(&self) -> bool {
        matches!(self.ty, Type::Filter)
    }

    /// Returns true if the rule is [Type::Detection]
    #[inline(always)]
    pub fn is_detection(&self) -> bool {
        matches!(self.ty, Type::Detection)
    }

    /// Returns rule's [Type]
    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.ty
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::net::IpAddr;
    use std::path::PathBuf;

    use super::*;
    use crate::{Event, FieldGetter, FieldValue};
    use gene_derive::{Event, FieldGetter};

    macro_rules! def_event {
            // Match for a struct with fields and field attributes
            ($struct_vis:vis struct $struct_name:ident { $($(#[$field_meta:meta])* $vis:vis $field_name:ident : $field_type:ty),* $(,)? }) => {
                #[derive(Debug, Event, FieldGetter)]
                #[event(id = 42, source = "test".into())]
                $struct_vis struct $struct_name {
                    $(
                        $(#[$field_meta])*
                        $vis $field_name: $field_type
                    ),*
                }
            };
        }

    macro_rules! fake_event {
        ($name:tt, $(($path:literal, $value:expr)),*) => {
            struct $name {}

            impl<'f> FieldGetter<'f> for $name{

                fn get_from_iter(&self, _: core::slice::Iter<'_, std::string::String>) -> Option<$crate::FieldValue<'_>>{
                    unimplemented!()
                }

                fn get_from_path(&self, path: &crate::XPath) -> Option<$crate::FieldValue<'_>> {
                    match path.to_string_lossy().as_ref() {
                        $($path => Some($value.into()),)*
                        _ => None,
                    }
                }
            }

            impl<'e> Event<'e> for $name {

                fn id(&self) -> i64{
                    42
                }

                fn source(&self) -> Cow<'_,str> {
                    "test".into()
                }
            }
        };
    }

    #[test]
    fn test_attack_re() {
        // all the things that should match
        ["T1234", "T1234.456", "TA0043", "S1088", "G1019"]
            .iter()
            .for_each(|s| {
                assert!(ATTACK_ID_RE.is_match(&s.to_uppercase()));
                assert!(ATTACK_ID_RE.is_match(&s.to_lowercase()))
            });

        // all the things that should not match
        ["t1245sTrInG", "t1245-456", "TA_1234", "S 0001"]
            .iter()
            .for_each(|s| assert!(!ATTACK_ID_RE.is_match(s)));
    }

    #[test]
    fn test_serialize_yaml() {
        let r = Rule {
            name: "test".into(),
            ..Default::default()
        };
        let s = serde_yaml::to_string(&r).unwrap();
        let d: Rule = serde_yaml::from_str(&s).unwrap();
        assert_eq!(d.name, "test");
    }

    #[test]
    fn test_rule_match() {
        let test = r#"
---
name: test
matches:
    $a: .data.exe.file == '/bin/ls'
    $b: .data.exe.size > '42'
    $c: .data.exe.size >= '43'
    $d: .data.exe.size < '4242'
    $e: .data.exe.size <= '43'
    $f: .data.exe.perm &= '0x40'
    $g: .data.exe.file ~= '^/bin/ls$'
    $h: .data.exe.file ~= '(?i:/BIN/LS)'
    $i: .data.exe.file == @.data.exe.file
    $k: .data.exe.file == @.data.exe.size
    $l: .data.exe.size == '43'
    $m: .data.exe.size == '0x2b'
condition: $a and $b and $c and $d and $e and $f and $g and $h and $i and not $k and $l and $m
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d)
            .map_err(|e| println!("{e}"))
            .unwrap();

        fake_event!(
            LsEvent,
            (".data.exe.file", "/bin/ls"),
            (".data.exe.size", 43),
            // this should trigger a string convertion to Number
            (".data.exe.perm", "0x10040")
        );

        assert!(cr.match_event(&(LsEvent {})).unwrap());
    }

    #[test]
    fn test_incompatible_fields() {
        let test = r#"
---
name: test
matches:
    $b: .data.exe.size > '42'
condition: $b
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        // we need to put something that cannot be transformed to a Number
        fake_event!(Dummy, (".data.exe.size", "42*3"));
        assert!(cr.match_event(&(Dummy {})).is_err_and(|e| {
            eprintln!("{e}");
            matches!(e.wrapped(), Error::Condition(_))
        }));
    }

    #[test]
    fn test_unknown_fields() {
        let test = r#"
---
name: test
matches:
    $b: .data.not_existing_field > '42'
condition: $b
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        fake_event!(Dummy, (".data.exe.size", "43"));
        assert!(cr.match_event(&(Dummy {})).is_err_and(|e| {
            eprintln!("{e}");
            matches!(e.wrapped(), Error::Condition(_))
        }));
    }

    #[test]
    fn test_unknown_operand() {
        let test = r#"
---
name: test
matches:
    $b: .data.not_existing_field > '42'
condition: $c
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        fake_event!(Dummy, (".data.exe.size", "43"));
        assert!(cr.match_event(&(Dummy {})).is_err_and(|e| {
            eprintln!("{e}");
            matches!(e.wrapped(), Error::Condition(_))
        }));
    }

    #[test]
    fn test_match_all_rule_operand() {
        let test = r#"
---
name: test
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        fake_event!(Dummy, (".data.exe.size", "43"));

        assert!(cr.match_event(&(Dummy {})).unwrap());
    }

    #[test]
    fn test_path_buf_matching() {
        let test = r#"
---
name: test
match-on:
    events:
        test: [42]
matches:
    $a: .path == "/some/path"
condition: $a
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                path: PathBuf,
            }
        );

        assert!(cr
            .match_event(
                &(Dummy {
                    path: PathBuf::from("/some/path")
                })
            )
            .unwrap());
    }

    #[test]
    fn test_ip_addr_matching() {
        let test = r#"
---
name: test
match-on:
    events:
        test: [42]
matches:
    $a: .ip == "8.8.4.4"
    #starts with 8.8
    $b: .ip ~= "^8\.8\."
condition: $a and $b
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        assert!(cr
            .match_event(
                &(Dummy {
                    ip: "8.8.4.4".parse().unwrap(),
                })
            )
            .unwrap());
    }

    #[test]
    fn test_templates() {
        let test = r#"
---
name: test
matches:
    $a: '{{path}} == "{{pattern}}"'
    $b: .ip ~= "^8\.8\."
condition: $a and $b
..."#;

        let mut templates = HashMap::new();
        templates.insert("path".to_string(), ".data.file.exe".to_string());
        templates.insert("pattern".into(), "8.8.4.4".into());

        let d = serde_yaml::from_str::<'_, Rule>(test)
            .unwrap()
            .apply_templates(&templates.into());

        let matches = d.matches.unwrap();
        let m = matches.get("$a").unwrap();
        assert_eq!(m, r#".data.file.exe == "8.8.4.4""#);
    }

    #[test]
    fn test_all_of_them() {
        let test = r#"
---
name: test
matches:
    $a: .ip == "8.8.4.4"
    $b: .ip ~= "^8\.8\."
condition: all of them
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        let event = Dummy {
            ip: "8.8.4.4".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_all_of_vars() {
        let test = r#"
---
name: test
matches:
    $ip1: .ip == "8.8.4.4"
    $ip2: .ip ~= "^8\.8\."
    $t : .ip == "4.4.4.4"
condition: all of $ip
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        let event = Dummy {
            ip: "8.8.4.4".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_any_of_them() {
        let test = r#"
---
name: test
matches:
    $a: .ip == "8.8.4.4"
    $b: .ip ~= "^8\.8\."
condition: any of them
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        let event = Dummy {
            ip: "8.8.42.42".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_any_of_vars() {
        let test = r#"
---
name: test
matches:
    $ip2: .ip == "42.42.42.42"
    $ip3: .ip == "8.8.4.4"
condition: any of $ip
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        for (ip, expect) in [
            ("42.42.42.42", true),
            ("8.8.4.4", true),
            ("255.0.0.0", false),
        ] {
            let event = Dummy {
                ip: ip.parse().unwrap(),
            };

            assert_eq!(cr.match_event(&event), Ok(expect));
        }
    }

    #[test]
    fn test_n_of_them() {
        let test = r#"
---
name: test
matches:
    $path1: .path == "/bin/ls"
    $ip2: .ip == "42.42.42.42"
    $ip3: .ip == "8.8.4.4"
condition: 2 of them
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                path: String,
                ip: IpAddr,
            }
        );

        let event = Dummy {
            path: "/bin/ls".into(),
            ip: "42.42.42.42".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_n_of_vars() {
        let test = r#"
---
name: test
matches:
    $path1: .path == "/bin/ls"
    $path2: .path == "/bin/true"
    $ip1: .ip == "42.42.42.42"
    $ip2: .ip == "8.8.4.4"
condition: 1 of $path or 1 of $ip
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                path: String,
                ip: IpAddr,
            }
        );

        let event = Dummy {
            path: "/bin/ls".into(),
            ip: "42.42.42.42".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));

        let event = Dummy {
            path: "/bin/true".into(),
            ip: "8.8.4.4".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_none_of_them() {
        let test = r#"
---
name: test
matches:
    $a: .ip == "8.8.4.4"
    $b: .ip ~= "^8\.8\."
condition: none of them
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        let event = Dummy {
            ip: "42.42.42.42".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_none_of_vars() {
        let test = r#"
---
name: test
matches:
    $ip1: .ip == "8.8.4.4"
    $ip2: .ip ~= "^8\.8\."
condition: none of $ip
..."#;

        let d: Rule = serde_yaml::from_str(test).unwrap();
        let cr = CompiledRule::try_from(d).unwrap();

        def_event!(
            pub struct Dummy {
                ip: IpAddr,
            }
        );

        let event = Dummy {
            ip: "42.42.42.42".parse().unwrap(),
        };

        assert_eq!(cr.match_event(&event), Ok(true));
    }

    #[test]
    fn test_deserialization_error() {
        let test = r#"
---
name: test
matches:
    $ip: .ip == "8.8.4.4"
    $ip: .ip ~= "^8\.8\."
condition: none of $ip
..."#;

        assert!(serde_yaml::from_str::<Rule>(test).is_err());
    }
}
