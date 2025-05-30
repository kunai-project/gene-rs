use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    compiler,
    rules::{self, bound_severity, CompiledRule},
    Compiler, Event, FieldValue,
};

use crate::FieldGetter;
use gene_derive::FieldGetter;

/// Structure holding information about the detection rules matching the [`Event`].
#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct Detection<'s> {
    /// Union of the rule names matching the event
    #[getter(skip)]
    pub rules: HashSet<Cow<'s, str>>,
    /// Union of tags defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<Cow<'s, str>>,
    /// Union of attack ids defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub attack: HashSet<Cow<'s, str>>,
    /// Union of actions defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<Cow<'s, str>>,
    /// Sum of all matching rules' severity (bounded to [MAX_SEVERITY](rules::MAX_SEVERITY))
    pub severity: u8,
}

/// Structure holding information about filters matching the [`Event`]
#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct Filter<'s> {
    /// Union of the rule names matching the event
    #[getter(skip)]
    pub rules: HashSet<Cow<'s, str>>,
    /// Union of tags defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<Cow<'s, str>>,
    /// Union of actions defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<Cow<'s, str>>,
}

/// Structure representing the result of an [`Event`] scanned by the
/// [`Engine`].
#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct ScanResult<'s> {
    /// If any contains [`Detection`] information resulting from the scan
    #[getter(skip)]
    pub detection: Option<Detection<'s>>,
    /// If any contains [`Filter`] information resulting from the scan
    #[getter(skip)]
    pub filter: Option<Filter<'s>>,
}

impl<'s> ScanResult<'s> {
    /// Creates an new [`ScanResult`]
    pub fn new() -> Self {
        ScanResult {
            ..Default::default()
        }
    }

    #[inline(always)]
    fn update(&mut self, r: &'s CompiledRule) {
        // we update matches only if it is not a filter rule
        if r.is_detection() {
            // update matches
            let detections = self.detection.get_or_insert_default();

            detections.rules.insert(Cow::from(&r.name));

            // updating attack info
            if !r.attack.is_empty() {
                r.attack.iter().for_each(|a| {
                    detections.attack.insert(a.into());
                });
            }

            // updating tags info
            if !r.tags.is_empty() {
                r.tags.iter().for_each(|t| {
                    detections.tags.insert(t.into());
                });
            }

            // we update actions
            if !r.actions.is_empty() {
                r.actions.iter().for_each(|a| {
                    detections.actions.insert(a.into());
                });
            }

            // we bound the severity of an event
            detections.severity = bound_severity(detections.severity + r.severity);
        } else if r.is_filter() {
            let filters = self.filter.get_or_insert_default();

            filters.rules.insert(Cow::from(&r.name));

            // updating tags info
            if !r.tags.is_empty() {
                r.tags.iter().for_each(|t| {
                    filters.tags.insert(t.into());
                });
            }

            // we update actions
            if !r.actions.is_empty() {
                r.actions.iter().for_each(|a| {
                    filters.actions.insert(a.into());
                });
            }
        }
    }

    /// Returns true if the scan result has matched filter rule with `name`
    #[inline(always)]
    pub fn contains_filter<S: AsRef<str>>(&self, name: S) -> bool {
        self.filter
            .as_ref()
            .map(|f| f.rules.contains(name.as_ref()))
            .unwrap_or_default()
    }

    /// Returns true if the scan results matched detection rule with `name`
    #[inline(always)]
    pub fn contains_detection<S: AsRef<str>>(&self, name: S) -> bool {
        self.detection
            .as_ref()
            .map(|d| d.rules.contains(name.as_ref()))
            .unwrap_or_default()
    }

    /// Returns true if the scan results contains a given tag
    #[inline(always)]
    pub fn contains_tag<S: AsRef<str>>(&self, tag: S) -> bool {
        self.detection
            .as_ref()
            .map(|d| d.tags.contains(tag.as_ref()))
            .or_else(|| self.filter.as_ref().map(|f| f.tags.contains(tag.as_ref())))
            .unwrap_or_default()
    }

    /// Returns true if the scan results contains a given action
    #[inline(always)]
    pub fn contains_action<S: AsRef<str>>(&self, action: S) -> bool {
        self.detection
            .as_ref()
            .map(|d| d.actions.contains(action.as_ref()))
            .or_else(|| {
                self.filter
                    .as_ref()
                    .map(|f| f.actions.contains(action.as_ref()))
            })
            .unwrap_or_default()
    }

    /// Returns true if the scan results contains a given attack id. No validity
    /// check is made on the id parameter, so if it is not looking like a MITRE
    /// ATT&CK id, this function will return false.
    #[inline(always)]
    pub fn contains_attack_id<S: AsRef<str>>(&self, id: S) -> bool {
        let attack_id = id.as_ref().to_ascii_uppercase();

        self.detection
            .as_ref()
            .map(|d| d.attack.contains(&Cow::from(&attack_id)))
            .unwrap_or_default()
    }

    /// Returns true if the scan results is considered as a detection (i.e. it matched some detection rules)
    #[inline(always)]
    pub fn has_detection(&self) -> bool {
        self.detection.is_some()
    }

    /// Returns true if the `ScanResult` is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.detection.is_none() && self.filter.is_none()
    }

    /// Returns true if the `ScanResult` **only matched** filter rule(s)
    #[inline(always)]
    pub fn has_only_filter(&self) -> bool {
        self.detection.is_none() && self.filter.is_some()
    }

    /// Returns true if the `ScanResult` **also matched** a filter rule
    #[inline(always)]
    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Rule(#[from] rules::Error),
}

/// Structure to represent an [`Event`] scanning engine.
/// Its role being to scan any structure implementing [`Event`] trait
/// with all the [Rules](Rule) loaded into the engine
///
/// # Example
///
/// ```
/// use gene_derive::{Event, FieldGetter};
/// use gene::{Compiler, Engine, Event,FieldGetter,FieldValue};
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
/// let mut c = Compiler::new();
/// c.load_rules_from_str(r#"
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
/// let mut e = Engine::try_from(c).unwrap();
/// let scan_res = e.scan(&event).unwrap().unwrap();
/// println!("{:#?}", scan_res);
///
/// assert!(scan_res.contains_detection("toast.it"));
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

impl TryFrom<Compiler> for Engine {
    type Error = compiler::Error;
    fn try_from(mut c: Compiler) -> Result<Self, Self::Error> {
        let mut e = Self::default();
        // we must be sure rules have been compiled
        c.compile()?;
        for r in c.compiled {
            e.insert_compiled(r);
        }
        Ok(e)
    }
}

impl Engine {
    /// creates a new event scanning engine
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    #[inline(always)]
    pub(crate) fn insert_compiled(&mut self, r: CompiledRule) {
        let has_deps = !r.depends.is_empty();

        // this is the index the rule is going to be inserted at
        let rule_idx = self.rules.len();
        self.names.insert(r.name.clone(), rule_idx);
        self.rules.push(r);

        // since we know all the dependent rules are there, we can cache
        // the list of dependencies and we never need to compute it again
        if has_deps {
            self.deps_cache
                .insert(rule_idx, self.dfs_dep_search(rule_idx));
        }

        // cache becomes outdated
        self.rules_cache.clear();
    }

    #[inline(always)]
    fn cached_rules(&mut self, src: String, id: i64) -> &[usize] {
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
                tmp.insert((r.severity, Cow::from(&r.name)), i);
            }
        }

        self.rules_cache
            .entry(key)
            .or_insert_with(|| tmp.values().rev().cloned().collect())
    }

    /// Returns the `Vec` of [CompiledRule] currently loaded in the engine
    pub fn compiled_rules(&self) -> &[CompiledRule] {
        &self.rules
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

    /// Scan an [`Event`] with all the rules loaded in the [`Engine`]
    pub fn scan<E>(
        &mut self,
        event: &E,
    ) -> Result<Option<ScanResult<'_>>, (Option<ScanResult<'_>>, Error)>
    where
        E: for<'e> Event<'e>,
    {
        let mut sr: Option<ScanResult<'_>> = None;
        let mut last_err: Option<Error> = None;

        let src = event.source();
        let id = event.id();

        let i_rules = self.cached_rules(src.into(), id).to_vec();
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
                            if states.contains_key(&Cow::Borrowed(r.name.as_str())) {
                                continue;
                            }

                            match r
                                .match_event_with_states(event, &states)
                                .map_err(Error::from)
                            {
                                Ok(ok) => {
                                    states.insert(Cow::Borrowed(&r.name), ok);
                                }
                                Err(e) => last_err = Some(e),
                            }
                        }
                    }
                }
            }

            // if the rule has already been matched in the process
            // of dependency matching of whatever rule
            let ok = match states.get(&Cow::Borrowed(r.name.as_str())) {
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

    macro_rules! fake_event {
        ($name:tt, id=$id:literal, source=$source:literal, $(($path:literal, $value:expr)),*) => {
            struct $name {}

            impl<'f> FieldGetter<'f> for $name{

                fn get_from_iter(&'f self, _: core::slice::Iter<'_, std::string::String>) -> Option<$crate::FieldValue<'f>>{
                    unimplemented!()
                }

                fn get_from_path(&self, path: &crate::XPath) -> Option<$crate::FieldValue> {
                    match path.to_string_lossy().as_ref() {
                        $($path => Some($value.into()),)*
                        _ => None,
                    }
                }
            }

            impl<'e> Event<'e> for $name {

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
        let mut c = Compiler::new();

        c.load_rules_from_str(
            r#"
name: test
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.contains_detection("test"));
        assert!(sr.contains_action("do_something"));
        assert!(!sr.has_filter());
        assert!(!sr.is_empty());
        assert!(!sr.has_only_filter());
    }

    #[test]
    fn test_basic_filter_scan() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: test
type: filter
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        // filter matches should not be put in matches
        assert!(!sr.contains_detection("test"));
        // actions should be propagated even if it is a filter
        assert!(sr.contains_action("do_something"));
        assert!(!sr.is_empty());
        assert!(sr.has_filter());
        assert!(sr.has_only_filter());
    }

    #[test]
    fn test_include_all_empty_filter() {
        // test that we must take all events when nothing is
        // included / excluded
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: test
type: filter
match-on:
    events:
        test: []
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        e.scan(&IpEvt {}).unwrap().unwrap();

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        e.scan(&PathEvt {}).unwrap().unwrap();
    }

    #[test]
    fn test_include_filter() {
        // test that only events included must be included
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: test
type: filter
match-on:
    events:
        test: [ 2 ]
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(IpEvt, id = 1, source = "test", (".ip", "8.8.4.4"));
        // not explicitly included so it should not be
        assert_eq!(e.scan(&IpEvt {}).unwrap(), None);

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        e.scan(&PathEvt {}).unwrap().unwrap();
    }

    #[test]
    fn test_exclude_filter() {
        // test that only stuff excluded must be excluded
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: test
type: filter
match-on:
    events:
        test: [ -1 ]
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
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
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: test
type: filter
match-on:
    events:
        test: [ -1, 2 ]
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

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
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: match
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
actions: ["do_something"]

---

name: filter
type: filter
match-on:
    events:
        test: [1]
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.contains_detection("match"));
        assert!(sr.contains_action("do_something"));
        assert!(sr.has_filter());
        assert!(!sr.has_only_filter());
    }

    #[test]
    fn test_match_with_tags() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: test.1
meta:
    tags: ['some:random:tag']
match-on:
    events:
        test: []

---

name: test.2
meta:
    tags: ['another:tag', 'some:random:tag']
match-on:
    events:
        test: []

"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.contains_detection("test.1"));
        assert!(sr.contains_detection("test.2"));
        assert!(sr.contains_tag("some:random:tag"));
        assert!(sr.contains_tag("another:tag"));
    }

    #[test]
    fn test_match_with_attack() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: detect.t4343
meta:
    attack:
        - t4343
match-on:
    events:
        test: []

---

name: detect.t4242
meta:
    attack:
        - t4242
match-on:
    events:
        test: []
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.contains_detection("detect.t4242"));
        assert!(sr.contains_detection("detect.t4343"));
        assert!(sr.contains_attack_id("t4242"));
        assert!(sr.contains_attack_id("t4343"));
    }

    #[test]
    fn test_rule_dependency() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: dep.rule
type: dependency
matches:
    $ip: .ip == '8.8.4.4'
condition: any of them

---

name: main
matches:
    $dep1: rule(dep.rule)
condition: all of them

---

name: match.all

"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(Dummy, id = 1, source = "test", (".ip", "8.8.4.4"));
        let sr = e.scan(&Dummy {}).unwrap().unwrap();
        assert!(sr.contains_detection("main"));
        assert!(!sr.contains_detection("dep.rule"));
        assert!(sr.contains_detection("match.all"));

        fake_event!(Dummy2, id = 1, source = "test", (".ip", "8.8.8.8"));
        let sr = e.scan(&Dummy2 {}).unwrap().unwrap();
        assert!(!sr.contains_detection("depends"));
        assert!(!sr.contains_detection("dep.rule"));
        assert!(sr.contains_detection("match.all"));
    }

    #[test]
    fn test_dep_cache() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: dep.rule
type: dependency
matches:
    $ip: .ip == '8.8.4.4'
condition: any of them

---

name: main
matches:
    $dep1: rule(dep.rule)
condition: all of them

---

name: multi.deps
matches:
    $dep1: rule(dep.rule)
    $dep2: rule(main)
    $dep3: rule(dep.rule)
    $dep4: rule(dep.rule)
condition: all of them
"#,
        )
        .unwrap();

        let e = Engine::try_from(c).unwrap();

        // we check the dep cache is correct
        assert_eq!(
            e.deps_cache
                .get(e.names.get("multi.deps").unwrap())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn test_compiled_rules() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: dep.rule
type: dependency

---

name: main
type: filter

---

name: multi.deps
type: detection
"#,
        )
        .unwrap();

        let e = Engine::try_from(c).unwrap();

        assert_eq!(
            e.compiled_rules().iter().filter(|c| c.is_filter()).count(),
            1
        );
        assert_eq!(
            e.compiled_rules()
                .iter()
                .filter(|c| c.is_detection())
                .count(),
            1
        );
    }
}
