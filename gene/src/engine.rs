use std::{
    collections::{HashMap, HashSet},
    io,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    rules::{self, bound_severity, CompiledRule},
    Event, FieldValue, Rule,
};

use crate::FieldGetter;
use gene_derive::FieldGetter;

/// structure representing the result of an [Event] scanned by the
/// [Engine]. It aggregates information about the rules matching a
/// given event as well as some meta data about it (tags, attack ids ...).
/// A severity score (sum of all matching rules severity bounded to [MAX_SEVERITY](rules::MAX_SEVERITY)) is also part of a `ScanResult`.
/// Some [Rules](Rule) matching an [Event] might be filter rules. In this
/// case only the [filtered](ScanResult::filtered) flag is updated.
#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct ScanResult {
    /// union of the rule names matching the event
    #[getter(skip)]
    pub rules: HashSet<String>,
    /// union of tags defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<String>,
    /// union of attack ids defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub attack: HashSet<String>,
    /// union of actions defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<String>,
    /// flag indicating whether a filter rule matched
    #[serde(skip)]
    pub filtered: bool,
    /// total severity score (bounded to [MAX_SEVERITY](rules::MAX_SEVERITY))
    pub severity: u8,
}

impl ScanResult {
    pub fn new() -> Self {
        ScanResult {
            ..Default::default()
        }
    }

    #[inline]
    fn update(&mut self, r: &CompiledRule) {
        // we update matches only if it is not a filter rule
        if !r.is_filter() {
            // update matches
            self.rules.insert(r.name.clone());

            // updating tags info
            self.tags = r.tags.union(&self.tags).cloned().collect();

            // updating attack info
            self.attack = r.attack.union(&self.attack).cloned().collect();

            // we update actions
            self.actions = r.actions.union(&self.actions).cloned().collect();

            // we bound the severity of an event
            self.severity = bound_severity(self.severity + r.severity);
        }

        self.filtered |= r.is_filter();
    }

    /// returns true if the scan results contains a given tag
    #[inline(always)]
    pub fn contains_tag<S: AsRef<str>>(&self, tag: S) -> bool {
        self.tags.contains(tag.as_ref())
    }

    /// returns true if the scan results contains a given action
    #[inline(always)]
    pub fn contains_action<S: AsRef<str>>(&self, action: S) -> bool {
        self.actions.contains(action.as_ref())
    }

    /// returns true if the scan results contains a given attack id. No validity
    /// check is made on the id parameter, so if it is not looking like a MITRE
    /// ATT&CK id, this function will return false.
    #[inline(always)]
    pub fn contains_attack_id<S: AsRef<str>>(&self, id: S) -> bool {
        self.attack.contains(&id.as_ref().to_ascii_uppercase())
    }

    /// returns true if the scan results is considered as a detection (i.e. it matched some detection rules)
    #[inline(always)]
    pub fn is_detection(&self) -> bool {
        !self.rules.is_empty()
    }

    /// returns true if the `ScanResult` is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && !self.is_filtered()
    }

    /// returns true if the `ScanResult` **only matched** filter rule(s)
    #[inline(always)]
    pub fn is_only_filter(&self) -> bool {
        self.rules.is_empty() && self.is_filtered()
    }

    /// returns true if the `ScanResult` **also matched** a filter rule
    #[inline(always)]
    pub fn is_filtered(&self) -> bool {
        self.filtered
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("duplicate rule name={0}")]
    DuplicateRule(String),
    #[error("{0}")]
    Deserialize(#[from] serde_yaml::Error),
    #[error("{0}")]
    Rule(#[from] rules::Error),
}

/// Structure to represent an [Event] scanning engine.
/// Its role being to scan any structure implementing [Event] trait
/// with all the [Rules](Rule) loaded into the engine
///
/// # Example
///
/// ```
/// use gene_derive::{Event, FieldGetter};
/// use gene::{Engine, Event,FieldGetter,FieldValue};
/// use std::borrow::Cow;
///
/// #[derive(FieldGetter)]
/// struct LogData {
///     a: String,
///     b: u64,
/// }
///
/// // we define our log event structure and derive Event
/// #[derive(Event, FieldGetter)]
/// #[event(id = self.event_id, source = "whatever".into())]
/// struct LogEvent<T> {
///    name: String,
///    some_field: u32,
///    event_id: i64,
///    data: LogData,
///    some_gen: T,
/// }
///
/// // We define a basic event
/// let event = LogEvent::<f64>{
///     name: "demo_event".into(),
///     some_field: 24,
///     event_id: 1,
///     data: LogData{
///         a: "some_inner_data".into(),
///         b: 42,
///     },
///     some_gen: 3.14,
/// };
///
/// let mut e = Engine::new();
/// e.load_rules_yaml_str(r#"
/// ---
/// name: toast.it
/// match-on:
///     events:
///         whatever: [1]
/// meta:
///     tags: [ "my:super:tag" ]
///     attack: [ T1234 ]
///     authors: [ me ]
///     comments:
///         - just a show case
/// matches:
///     $n: .name == "demo_event"
///     $pi: .some_gen >= '3.14'
///     $a: .data.a ~= '(?i:some_INNER.*)'
///     $b: .data.b <= '42'
/// condition: $n and $pi and $a and $b
/// ..."#).unwrap();
///
/// let scan_res = e.scan(&event).unwrap().unwrap();
/// println!("{:#?}", scan_res);
///
/// assert!(scan_res.rules.contains("toast.it"));
/// assert!(scan_res.contains_tag("my:super:tag"));
/// assert!(scan_res.contains_attack_id("T1234"));
/// ```
#[derive(Debug, Default)]
pub struct Engine {
    names: HashMap<String, usize>,
    rules: Vec<CompiledRule>,
    cache: HashMap<(String, i64), Vec<usize>>,
}

impl Engine {
    /// creates a new event scanning engine
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// insert a rule into the engine
    #[inline]
    pub fn insert_rule(&mut self, r: Rule) -> Result<(), Error> {
        if r.is_disabled() {
            return Ok(());
        }

        if self.names.contains_key(&r.name) {
            return Err(Error::DuplicateRule(r.name));
        }
        // we need to be sure nothing can fail beyound this point
        let compiled: CompiledRule = r.try_into()?;

        self.names.insert(compiled.name.clone(), self.rules.len());
        self.rules.push(compiled);
        // cache becomes outdated
        self.cache.clear();

        Ok(())
    }

    /// load rule(s) defined in a string YAML documents, into the engine
    pub fn load_rules_yaml_str<S: AsRef<str>>(&mut self, s: S) -> Result<(), Error> {
        for document in serde_yaml::Deserializer::from_str(s.as_ref()) {
            self.insert_rule(Rule::deserialize(document)?)?;
        }
        Ok(())
    }

    /// loads rules from a [io::Read] containing YAML serialized data
    pub fn load_rules_yaml_reader<R: io::Read>(&mut self, r: R) -> Result<(), Error> {
        for document in serde_yaml::Deserializer::from_reader(r) {
            self.insert_rule(Rule::deserialize(document)?)?;
        }
        Ok(())
    }

    #[inline(always)]
    fn cached_rules(&mut self, src: String, id: i64) -> Vec<usize> {
        let key = (src, id);
        let mut tmp = vec![];
        if !self.cache.contains_key(&key) {
            for (i, r) in self.rules.iter().enumerate() {
                if r.can_match_on(&key.0, id) {
                    tmp.push(i)
                }
            }
        }
        self.cache.entry(key).or_insert(tmp).to_vec()
    }

    /// returns the number of rules loaded in the engine
    #[inline(always)]
    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }

    /// returns true if no rules are loaded in the engine
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// scan an [Event] with all the rules loaded in the [Engine]
    pub fn scan<E: Event>(
        &mut self,
        event: &E,
    ) -> Result<Option<ScanResult>, (Option<ScanResult>, Error)> {
        let mut sr: Option<ScanResult> = None;
        let mut last_err: Option<Error> = None;

        let src = event.source();
        let id = event.id();

        let i_rules = self.cached_rules(src.into(), id);
        let iter = i_rules.iter().map(|&i| self.rules.get(i).unwrap());

        for r in iter {
            match r.match_event(event).map_err(Error::from) {
                Ok(ok) => {
                    if ok {
                        if sr.is_none() {
                            sr = Some(ScanResult::new())
                        }
                        sr.as_mut().unwrap().update(r)
                    }
                }
                Err(e) => last_err = Some(e),
            };
        }

        if let Some(err) = last_err {
            return Err((sr, err));
        }

        Ok(sr)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! rule {
        ($rule: literal) => {{
            let d: Rule = serde_yaml::from_str($rule).unwrap();
            d
        }};
    }

    macro_rules! fake_event {
        ($name:tt, id=$id:literal, source=$source:literal, $(($path:literal, $value:expr)),*) => {
            struct $name {}

            impl FieldGetter for $name{

                fn get_from_iter(&self, _: core::slice::Iter<'_, std::string::String>) -> Option<$crate::FieldValue>{
                    unimplemented!()
                }

                fn get_from_path(&self, path: &crate::XPath) -> Option<$crate::FieldValue> {
                    match path.to_string_lossy().as_ref() {
                        $($path => Some($value.into()),)*
                        _ => None,
                    }
                }
            }

            impl Event for $name {

                fn id(&self) -> i64{
                    $id
                }

                fn source(&self) -> std::borrow::Cow<'_,str> {
                    $source.into()
                }
            }
        };
    }

    #[test]
    fn test_basic_match_scan() {
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.rules.contains("test"));
        assert!(sr.contains_action("do_something"));
        assert!(!sr.is_filtered());
        assert!(!sr.is_empty());
        assert!(!sr.is_only_filter());
    }

    #[test]
    fn test_basic_filter_scan() {
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
params:
    filter: true
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        // filter matches should not be put in matches
        assert!(!sr.rules.contains("test"));
        // actions are not taken in action
        assert!(!sr.contains_action("do_something"));
        assert!(!sr.is_empty());
        assert!(sr.is_filtered());
        assert!(sr.is_only_filter());
    }

    #[test]
    fn test_include_all_empty_filter() {
        // test that we must take all events when nothing is
        // included / excluded
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
params:
    filter: true
match-on:
    events:
        test: []
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        e.scan(&IpEvt {}).unwrap().unwrap();

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        e.scan(&PathEvt {}).unwrap().unwrap();
    }

    #[test]
    fn test_include_filter() {
        // test that only events included must be included
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
params:
    filter: true
match-on:
    events:
        test: [ 2 ]
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        // not explicitly included so it should not be
        assert_eq!(e.scan(&IpEvt {}).unwrap(), None);

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        e.scan(&PathEvt {}).unwrap().unwrap();
    }

    #[test]
    fn test_exclude_filter() {
        // test that only stuff excluded must be excluded
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
params:
    filter: true
match-on:
    events:
        test: [ -1 ]
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        assert_eq!(e.scan(&IpEvt {}).unwrap(), None);

        // if not explicitely excluded it is included
        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        assert!(e.scan(&PathEvt {}).unwrap().is_some());

        fake_event!(DnsEvt, id = 3, source = "test", (".domain", "test.com"));
        assert!(e.scan(&DnsEvt {}).unwrap().is_some());
    }

    #[test]
    fn test_mix_include_exclude_filter() {
        // test that when include and exclude filters are
        // specified we take only events in those
        let mut e = Engine::new();
        let r = rule!(
            r#"
---
name: test
params:
    filter: true
match-on:
    events:
        test: [ -1, 2 ]
..."#
        );

        e.insert_rule(r).unwrap();
        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        assert_eq!(e.scan(&IpEvt {}).unwrap(), None);

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        assert!(e.scan(&PathEvt {}).unwrap().is_some());

        // this has not been excluded but not included so it should
        // not match
        fake_event!(DnsEvt, id = 3, source = "test", (".domain", "test.com"));
        assert_eq!(e.scan(&DnsEvt {}).unwrap(), None);
    }

    #[test]
    fn test_match_and_filter() {
        let mut e = Engine::new();
        let _match = rule!(
            r#"
---
name: match
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]
..."#
        );

        let filter = rule!(
            r#"
---
name: filter
params:
    filter: true
match-on:
    events:
        test: [1]
..."#
        );

        e.insert_rule(_match).unwrap();
        e.insert_rule(filter).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.rules.contains("match"));
        assert!(sr.contains_action("do_something"));
        assert!(sr.is_filtered());
        assert!(!sr.is_only_filter());
    }

    #[test]
    fn test_match_with_tags() {
        let mut e = Engine::new();
        let t4343 = rule!(
            r#"
---
name: test.1
meta:
    tags: ['some:random:tag']
match-on:
    events:
        test: []
..."#
        );

        let t4242 = rule!(
            r#"
---
name: test.2
meta:
    tags: ['another:tag', 'some:random:tag']
match-on:
    events:
        test: []
..."#
        );

        e.insert_rule(t4242).unwrap();
        e.insert_rule(t4343).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.rules.contains("test.1"));
        assert!(sr.rules.contains("test.2"));
        assert!(sr.tags.contains("some:random:tag"));
        assert!(sr.tags.contains("another:tag"));
    }

    #[test]
    fn test_match_with_attack() {
        let mut e = Engine::new();
        let t4343 = rule!(
            r#"
---
name: detect.t4343
meta:
    attack:
        - t4343
match-on:
    events:
        test: []
..."#
        );

        let t4242 = rule!(
            r#"
---
name: detect.t4242
meta:
    attack:
        - t4242
match-on:
    events:
        test: []
..."#
        );

        e.insert_rule(t4242).map_err(|e| println!("{e}")).unwrap();
        e.insert_rule(t4343).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.rules.contains("detect.t4242"));
        assert!(sr.rules.contains("detect.t4343"));
        assert!(sr.contains_attack_id("t4242"));
        assert!(sr.contains_attack_id("t4343"));
    }
}
