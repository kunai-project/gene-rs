use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
            if !r.tags.is_empty() {
                self.tags = r.tags.union(&self.tags).cloned().collect();
            }

            // updating attack info
            if !r.attack.is_empty() {
                self.attack = r.attack.union(&self.attack).cloned().collect();
            }

            // we bound the severity of an event
            self.severity = bound_severity(self.severity + r.severity);
        }

        // we update actions
        if !r.actions.is_empty() {
            self.actions = r.actions.union(&self.actions).cloned().collect();
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
    #[error("duplicate rule={0}")]
    DuplicateRule(String),
    #[error("unknown rule dependency in rule={0}")]
    UnknownRuleDependency(String),
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
#[derive(Debug, Default, Clone)]
pub struct Engine {
    // rule names mapping to rule index in rules member
    names: HashMap<String, usize>,
    // all the rules in the engine
    rules: Vec<CompiledRule>,
    // cache the list of rules indexes to match a given (source, id)
    // key: (source, event_id)
    // value: vector of rule indexes
    rules_cache: HashMap<(String, i64), Vec<usize>>,
    // cache rules dependencies
    // key: rule index
    // value: vector of dependency indexes
    deps_cache: HashMap<usize, Vec<usize>>,
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
        let has_deps = !compiled.depends.is_empty();

        // We verify that all rules we depend on are known.
        // The fact that rule dependencies must be known makes
        // circular references impossible
        for dep in compiled.depends.iter() {
            self.names
                .get(dep)
                .ok_or(Error::UnknownRuleDependency(dep.clone()))?;
        }

        // this is the index the rule is going to be inserted at
        let rule_idx = self.rules.len();
        self.names.insert(compiled.name.clone(), rule_idx);
        self.rules.push(compiled);

        // since we know all the dependent rules are there, we can cache
        // the list of dependencies and we never need to compute it again
        if has_deps {
            self.deps_cache
                .insert(rule_idx, self.dfs_dep_search(rule_idx));
        }

        // cache becomes outdated
        self.rules_cache.clear();

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
        let mut tmp = BTreeMap::new();
        if !self.rules_cache.contains_key(&key) {
            for (i, r) in self
                .rules
                .iter()
                // !!! do not enumerate after a filter otherwise indexes will
                // not be the good ones
                .enumerate()
                // we take only filter and detection rules
                .filter(|(_, r)| r.is_filter() || r.is_detection())
                // we take only rules that can match on that kind of event
                .filter(|(_, r)| r.can_match_on(&key.0, id))
            {
                tmp.insert((r.severity, r.name.clone()), i);
            }
        }

        self.rules_cache
            .entry(key)
            .or_insert(tmp.values().rev().cloned().collect())
            .to_vec()
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

    /// Dfs recursive dependency finding
    /// There is no check for circular references as those are impossibele
    /// due to the fact that a rule cannot depend on a non existing rule.
    #[inline(always)]
    fn dfs_dep_search(&self, rule_idx: usize) -> Vec<usize> {
        // recursive function
        fn rule_dep_search_rec(
            eng: &Engine,
            rule_idx: usize,
            dfs: &mut Vec<usize>,
            mark: &mut HashSet<usize>,
        ) {
            for req_name in eng.rules[rule_idx].depends.iter() {
                if let Some(&dep) = eng.names.get(req_name) {
                    rule_dep_search_rec(eng, dep, dfs, mark);
                    if !mark.contains(&dep) {
                        dfs.push(dep);
                        mark.insert(dep);
                    }
                }
            }
        }

        let mut req = HashSet::new();
        let mut dfs = Vec::new();
        rule_dep_search_rec(self, rule_idx, &mut dfs, &mut req);
        dfs
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
        let mut states = HashMap::with_capacity(i_rules.len());

        for i in i_rules {
            // this is equivalent to an OOB error but this should not happen
            let r = self.rules.get(i).unwrap();

            if !r.depends.is_empty() {
                debug_assert!(self.deps_cache.contains_key(&i));
                // there are some dependent rules to match against
                if let Some(deps) = self.deps_cache.get(&i) {
                    // we match every dependency of the rule first
                    for &r_i in deps.iter() {
                        if let Some(r) = self.rules.get(r_i) {
                            // we don't need to compute rule again
                            // NB: rule might be used in several places and already computed
                            if states.contains_key(&r.name) {
                                continue;
                            }

                            match r
                                .match_event_with_states(event, &states)
                                .map_err(Error::from)
                            {
                                Ok(ok) => {
                                    states.insert(r.name.clone(), ok);
                                }
                                Err(e) => last_err = Some(e),
                            }
                        }
                    }
                }
            }

            // if the rule has already been matched in the process
            // of dependency matching of whatever rule
            let ok = match states.get(&r.name) {
                Some(&ok) => ok,
                None => {
                    match r
                        .match_event_with_states(event, &states)
                        .map_err(Error::from)
                    {
                        Ok(ok) => ok,
                        Err(e) => {
                            last_err = Some(e);
                            false
                        }
                    }
                }
            };

            // we process scan result
            if ok {
                sr.get_or_insert(ScanResult::new()).update(r);
            }
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
type: filter
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
        // actions should be propagated even if it is a filter
        assert!(sr.contains_action("do_something"));
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
type: filter
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
type: filter
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
type: filter
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
type: filter
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
type: filter
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

    #[test]
    fn test_rule_dependency() {
        let mut e = Engine::new();

        e.insert_rule(rule!(
            r#"
name: dep.rule
type: dependency
matches:
    $ip: .ip == '8.8.4.4'
condition: any of them
"#
        ))
        .unwrap();

        e.insert_rule(rule!(
            r#"
name: main
matches:
    $dep1: rule(dep.rule)
condition: all of them
"#
        ))
        .unwrap();

        e.insert_rule(rule!(
            r#"
name: match.all
"#
        ))
        .unwrap();

        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.rules.contains("main"));
        assert!(!sr.rules.contains("dep.rule"));
        assert!(sr.rules.contains("match.all"));

        fake_event!(Dummy2, id = 1, source = "test", (".ip", "8.8.8.8"));
        let sr = e.scan(&Dummy2 {}).unwrap().unwrap();
        assert!(!sr.rules.contains("depends"));
        assert!(!sr.rules.contains("dep.rule"));
        assert!(sr.rules.contains("match.all"));
    }

    #[test]
    fn test_load_rule_unk_dep() {
        let mut e = Engine::new();

        let res = e.insert_rule(rule!(
            r#"
name: test
matches:
    $dep: rule(unknown.rule)
condition: any of them
"#
        ));

        assert!(matches!(res, Err(Error::UnknownRuleDependency(_))));
    }

    #[test]
    fn test_load_circular_rule() {
        let mut e = Engine::new();

        let res = e.insert_rule(rule!(
            r#"
name: test
matches:
    $dep: rule(test)
condition: any of them
"#
        ));

        // when dependencies are checked, rule is not yet inserted in the engine
        // so it should result in an UnknownRuleDependency
        assert!(matches!(res, Err(Error::UnknownRuleDependency(_))));
    }

    #[test]
    fn test_dep_cache() {
        let mut e = Engine::new();

        e.insert_rule(rule!(
            r#"
name: dep.rule
type: dependency
matches:
    $ip: .ip == '8.8.4.4'
condition: any of them
"#
        ))
        .unwrap();

        e.insert_rule(rule!(
            r#"
name: main
matches:
    $dep1: rule(dep.rule)
condition: all of them
"#
        ))
        .unwrap();

        e.insert_rule(rule!(
            r#"
name: multi.deps
matches:
    $dep1: rule(dep.rule)
    $dep2: rule(main)
    $dep3: rule(dep.rule)
    $dep4: rule(dep.rule)
condition: all of them
"#
        ))
        .unwrap();

        // we check the dep cache is correct
        assert_eq!(
            e.deps_cache
                .get(e.names.get("multi.deps").unwrap())
                .unwrap()
                .len(),
            2
        );
    }
}
