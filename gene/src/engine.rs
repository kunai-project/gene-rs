use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    compiler,
    rules::{self, bound_severity, CompiledRule, Decision},
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

/// Enum representing the decision state for filters and detections.
#[derive(Debug)]
pub enum ScanDecision<'s, T>
where
    T: Default,
{
    /// Exclude decision variant.
    ///
    /// When a component is excluded, it may optionally include the name of the excluding
    /// rule.
    Exclude(Option<Cow<'s, str>>),

    /// Include decision variant.
    ///
    /// When a component is included, this variant contains data containing inclusion
    /// information.
    Include(T),
}

impl<'s, T> ScanDecision<'s, T>
where
    T: Default,
{
    #[inline]
    fn default_exclude() -> Self {
        Self::Exclude(None)
    }

    #[inline(always)]
    fn exclude(&mut self, s: &'s str) {
        *self = Self::Exclude(Some(Cow::Borrowed(s)))
    }

    #[inline]
    fn get_include_or_insert_default(&mut self) -> Option<&mut T> {
        match self {
            Self::Include(i) => Some(i),
            Self::Exclude(None) => {
                *self = Self::Include(T::default());
                let Self::Include(i) = self else {
                    unreachable!("Exclude variant should never be in this state")
                };
                Some(i)
            }
            Self::Exclude(Some(_)) => None,
        }
    }

    /// Consumes the decision and returns the included data if this is an `Include` variant.
    ///
    /// Returns `None` if this is an `Exclude` variant. This method consumes `self`,
    /// transferring ownership of the included data to the caller.
    #[inline(always)]
    pub fn take_include(self) -> Option<T> {
        match self {
            Self::Include(i) => Some(i),
            _ => None,
        }
    }

    /// Returns a reference to the included data if this is an `Include` variant.
    ///
    /// Returns `None` if this is an `Exclude` variant. This is a non-consuming
    /// method that provides borrowed access to the included data.
    #[inline(always)]
    pub fn get_include(&self) -> Option<&T> {
        match self {
            Self::Include(i) => Some(i),
            _ => None,
        }
    }

    /// Returns a reference to the exclude reason if this is an `Exclude` variant.
    ///
    /// Returns `None` if this is an `Include` variant. The returned value is
    /// an `Option<&Option<Cow<'_, str>>>` representing the optional exclusion rule.
    #[inline(always)]
    pub fn get_exclude(&self) -> Option<&Option<Cow<'_, str>>> {
        match self {
            Self::Exclude(i) => Some(i),
            _ => None,
        }
    }

    /// Returns `true` if this is an `Include` variant.
    #[inline(always)]
    pub fn is_include(&self) -> bool {
        matches!(self, Self::Include(_))
    }

    /// Returns `true` if this is an `Exclude` variant.
    #[inline(always)]
    pub fn is_exclude(&self) -> bool {
        matches!(self, Self::Exclude(_))
    }

    /// Returns `true` if this is an `Exclude` variant with no specific rule.
    ///
    /// This indicates a default exclusion where `Exclude(None)` was used,
    /// distinguishing it from exclusions from a specific exclusion rule.
    #[inline(always)]
    pub fn is_default_exclude(&self) -> bool {
        matches!(self, Self::Exclude(None))
    }
}

/// Structure representing the result of an [`Event`] scanned by the [`Engine`].
///
/// The `ScanResult` contains the outcome of scanning an event against all loaded rules,
/// including both detection and filter rule matches. It uses [`ScanDecision`] to track
/// whether the decision state implemented by the rules.
///
/// # Type Parameters
///
/// - `'s`: Lifetime parameter for borrowed data from the original event and rules
///
/// # Fields
///
/// - `filter`: Filter rule scan decision and data
/// - `detection`: Detection rule scan decision and data
///
/// # Usage
///
/// This struct is returned by [`Engine::scan()`] and provides access to all matching
/// rules, their metadata (tags, actions, attack IDs), and severity information.
#[derive(Debug)]
pub struct ScanResult<'s> {
    /// Filter rule scan decision and data.
    ///
    /// Contains the decision (include/exclude) and associated filter data for
    /// any filter rules that matched the scanned event.
    pub filter: ScanDecision<'s, Filter<'s>>,

    /// Detection rule scan decision and data.
    ///
    /// Contains the decision (include/exclude) and associated detection data for
    /// any detection rules that matched the scanned event.
    pub detection: ScanDecision<'s, Detection<'s>>,
}

impl<'s> ScanResult<'s> {
    fn default_exclude() -> Self {
        Self {
            filter: ScanDecision::<'s, Filter<'s>>::default_exclude(),
            detection: ScanDecision::<'s, Detection<'s>>::default_exclude(),
        }
    }

    #[inline(always)]
    fn update_include(&mut self, r: &'s CompiledRule) {
        // we update matches only if it is not a filter rule
        if r.is_detection() {
            // update matches
            let Some(detections) = self.detection.get_include_or_insert_default() else {
                return;
            };

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
            let Some(filters) = self.filter.get_include_or_insert_default() else {
                return;
            };

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

    #[inline]
    fn update_exclude(&mut self, r: &'s CompiledRule) {
        if r.is_detection() {
            self.detection.exclude(&r.name);
        } else if r.is_filter() {
            self.filter.exclude(&r.name);
        }
    }

    /// Returns the decision for filter rules in this scan result.
    ///
    /// Returns `Decision::Include` if filter rules are included, or `Decision::Exclude`
    /// if they are excluded from the result.
    #[inline]
    pub fn filter_decision(&self) -> Decision {
        if self.filter.is_include() {
            Decision::Include
        } else {
            Decision::Exclude
        }
    }

    /// Returns the decision for detection rules in this scan result.
    ///
    /// Returns `Decision::Include` if detection rules are included, or `Decision::Exclude`
    /// if they are excluded from the result.
    #[inline]
    pub fn detection_decision(&self) -> Decision {
        if self.detection.is_include() {
            Decision::Include
        } else {
            Decision::Exclude
        }
    }

    /// Returns `true` if this scan result represents the default exclude decision.
    ///
    /// A scan result is considered a default exclude when both detection and filter
    /// decisions are set to exclude their default values.
    #[inline]
    pub fn is_default_exclude(&self) -> bool {
        self.detection.is_default_exclude() && self.filter.is_default_exclude()
    }

    /// Returns `true` if this scan result contains only included filter rules.
    ///
    /// This is `true` when detection rules are excluded and filter rules are included,
    /// indicating that only filter rules matched during scanning.
    #[inline(always)]
    pub fn is_only_filter_include(&self) -> bool {
        self.detection_decision().is_exclude() && self.filter_decision().is_include()
    }

    /// Returns `true` if the scan result includes a filter rule with the given name.
    ///
    /// # Examples
    ///
    /// ```
    /// use gene::{Compiler, Engine};
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.load_rules_from_str(r#"
    /// name: test.filter
    /// type: filter
    /// matches:
    ///     $a: .field == "value"
    /// condition: $a
    /// "#).unwrap();
    ///
    /// let mut engine = Engine::try_from(compiler).unwrap();
    /// // ... scan an event ...
    /// // let scan_result = engine.scan(&event).unwrap();
    /// // assert!(scan_result.includes_filter("test.filter"));
    /// ```
    #[inline(always)]
    pub fn includes_filter<S: AsRef<str>>(&self, name: S) -> bool {
        self.filter
            .get_include()
            .map(|f| f.rules.contains(name.as_ref()))
            .unwrap_or_default()
    }

    /// Returns `true` if the scan result includes a detection rule with the given name.
    ///
    /// # Examples
    ///
    /// ```
    /// use gene::{Compiler, Engine};
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.load_rules_from_str(r#"
    /// name: test.detection
    /// matches:
    ///     $a: .field == "value"
    /// condition: $a
    /// "#).unwrap();
    ///
    /// let mut engine = Engine::try_from(compiler).unwrap();
    /// // ... scan an event ...
    /// // let scan_result = engine.scan(&event).unwrap();
    /// // assert!(scan_result.includes_detection("test.detection"));
    /// ```
    #[inline(always)]
    pub fn includes_detection<S: AsRef<str>>(&self, name: S) -> bool {
        self.detection
            .get_include()
            .map(|d| d.rules.contains(name.as_ref()))
            .unwrap_or_default()
    }

    /// Returns `true` if the scan result includes the specified tag.
    ///
    /// Checks both detection and filter rules for the given tag.
    ///
    /// # Examples
    ///
    /// ```
    /// use gene::{Compiler, Engine};
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.load_rules_from_str(r#"
    /// name: test.rule
    /// meta:
    ///     tags: ["network", "suspicious"]
    /// matches:
    ///     $a: .field == "value"
    /// condition: $a
    /// "#).unwrap();
    ///
    /// let mut engine = Engine::try_from(compiler).unwrap();
    /// // ... scan an event ...
    /// // let scan_result = engine.scan(&event).unwrap();
    /// // assert!(scan_result.includes_tag("network"));
    /// ```
    #[inline(always)]
    pub fn includes_tag<S: AsRef<str>>(&self, tag: S) -> bool {
        self.detection
            .get_include()
            .map(|d| d.tags.contains(tag.as_ref()))
            .or_else(|| {
                self.filter
                    .get_include()
                    .map(|f| f.tags.contains(tag.as_ref()))
            })
            .unwrap_or_default()
    }

    /// Returns `true` if the scan result includes the specified action.
    ///
    /// Checks both detection and filter rules for the given action.
    ///
    /// # Examples
    ///
    /// ```
    /// use gene::{Compiler, Engine};
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.load_rules_from_str(r#"
    /// name: test.rule
    /// actions: ["alert", "log"]
    /// matches:
    ///     $a: .field == "value"
    /// condition: $a
    /// "#).unwrap();
    ///
    /// let mut engine = Engine::try_from(compiler).unwrap();
    /// // ... scan an event ...
    /// // let scan_result = engine.scan(&event).unwrap();
    /// // assert!(scan_result.includes_action("alert"));
    /// ```
    #[inline(always)]
    pub fn includes_action<S: AsRef<str>>(&self, action: S) -> bool {
        self.detection
            .get_include()
            .map(|d| d.actions.contains(action.as_ref()))
            .or_else(|| {
                self.filter
                    .get_include()
                    .map(|f| f.actions.contains(action.as_ref()))
            })
            .unwrap_or_default()
    }

    /// Returns `true` if the scan result includes the specified MITRE ATT&CK ID.
    ///
    /// The comparison is case-insensitive. No validation is performed on the input
    /// ID - if it does not conform to MITRE ATT&CK ID format, this will return `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// use gene::{Compiler, Engine};
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.load_rules_from_str(r#"
    /// name: test.rule
    /// meta:
    ///     attack: ["T1059"]
    /// matches:
    ///     $a: .field == "value"
    /// condition: $a
    /// "#).unwrap();
    ///
    /// let mut engine = Engine::try_from(compiler).unwrap();
    /// // ... scan an event ...
    /// // let scan_result = engine.scan(&event).unwrap();
    /// // assert!(scan_result.includes_attack_id("t1059"));
    /// // assert!(scan_result.includes_attack_id("T1059"));
    /// ```
    #[inline(always)]
    pub fn includes_attack_id<S: AsRef<str>>(&self, id: S) -> bool {
        let attack_id = id.as_ref().to_ascii_uppercase();

        self.detection
            .get_include()
            .map(|d| d.attack.contains(&Cow::from(&attack_id)))
            .unwrap_or_default()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Rule(#[from] rules::Error),
}

#[derive(Debug, Default, Clone)]
struct RuleCacheEntry {
    filters: Vec<usize>,
    detections: Vec<usize>,
}

/// Structure to represent an [`Event`] scanning engine.
/// Its role being to scan any structure implementing [`Event`] trait
/// with all the [`rules::Rule`] loaded into the engine
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
/// let scan_res = e.scan(&event).unwrap();
/// println!("{:#?}", scan_res);
///
/// assert!(scan_res.includes_detection("toast.it"));
/// assert!(scan_res.includes_tag("my:super:tag"));
/// assert!(scan_res.includes_attack_id("T1234"));
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
    rules_cache: HashMap<(String, i64), RuleCacheEntry>,
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
    fn cache_rules(&mut self, src: String, id: i64) {
        let key = (src, id);
        let mut tmp_filters = BTreeMap::new();
        let mut tmp_detections = BTreeMap::new();

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
                if r.is_filter() {
                    tmp_filters.insert(((r.decision, r.severity), Cow::from(&r.name)), i);
                } else if r.is_detection() {
                    tmp_detections.insert(((r.decision, r.severity), Cow::from(&r.name)), i);
                }
            }

            self.rules_cache.insert(
                key,
                RuleCacheEntry {
                    filters: tmp_filters.values().rev().cloned().collect(),
                    detections: tmp_detections.values().rev().cloned().collect(),
                },
            );
        }
    }

    #[inline(always)]
    fn cached_rules(&self, src: String, id: i64) -> Option<&RuleCacheEntry> {
        let key = (src, id);
        self.rules_cache.get(&key)
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
    /// There is no check for circular references as those are impossible
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
    pub fn scan<E>(&mut self, event: &E) -> Result<ScanResult<'_>, Box<(ScanResult<'_>, Error)>>
    where
        E: for<'e> Event<'e>,
    {
        let mut sr = ScanResult::default_exclude();
        let mut last_err: Option<Error> = None;

        let src = event.source();
        let id = event.id();

        self.cache_rules(src.clone().into(), id);
        let cached_rules = self.cached_rules(src.into(), id).unwrap();
        let mut states = HashMap::new();

        // we iterate over each because we don't want exclude rules from filter
        // exclude to impact detection include and vice versa
        for it in [cached_rules.filters.iter(), cached_rules.detections.iter()] {
            for i in it {
                // this is equivalent to an OOB error but this should not happen
                let r = self.rules.get(*i).unwrap();

                if !r.depends.is_empty() {
                    debug_assert!(self.deps_cache.contains_key(i));
                    // there are some dependent rules to match against
                    if let Some(deps) = self.deps_cache.get(i) {
                        // we match every dependency of the rule first
                        for &r_i in deps.iter() {
                            if let Some(r) = self.rules.get(r_i) {
                                // we don't need to compute rule again
                                // NB: rule might be used in several places and already computed
                                if states.contains_key(&Cow::Borrowed(r.name.as_str())) {
                                    continue;
                                }

                                // if the rule cannot match we don't need to go further
                                if !r.can_match_on(event.source(), id) {
                                    states.insert(Cow::Borrowed(r.name.as_str()), false);
                                    continue;
                                }

                                match r
                                    .match_event_with_states(event, &states)
                                    .map_err(Error::from)
                                {
                                    Ok(ok) => {
                                        states.insert(Cow::Borrowed(r.name.as_str()), ok);
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
                    if r.decision.is_include() {
                        sr.update_include(r);
                    } else {
                        sr.update_exclude(r);
                        break;
                    }
                }
            }
        }

        if let Some(err) = last_err {
            return Err((sr, err).into());
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

                fn get_from_path(&self, path: &crate::XPath) -> Option<$crate::FieldValue<'_>> {
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
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("test"));
        assert!(sr.includes_action("do_something"));
        assert!(!sr.filter_decision().is_include());
        assert!(!sr.is_default_exclude());
        assert!(!sr.is_only_filter_include());
    }

    #[test]
    fn test_basic_match_scan_vector() {
        let mut c = Compiler::new();

        c.load_rules_from_str(
            r#"
name: test
matches:
    $a: .ip ~= "^8\.8\."
condition: $a
"#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(
            Dummy,
            id = 1,
            source = "test",
            (".ip", vec!["9.9.9.9", "8.8.4.4"])
        );
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.detection_decision().is_include());
        assert!(sr.includes_detection("test"));
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
        let sr = e.scan(&Dummy {}).unwrap();
        // filter matches should not be put in matches
        assert!(!sr.includes_detection("test"));
        // actions should be propagated even if it is a filter
        assert!(sr.includes_action("do_something"));
        assert!(!sr.is_default_exclude());
        assert!(sr.filter_decision().is_include());
        assert!(sr.is_only_filter_include());
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
        e.scan(&IpEvt {}).unwrap();

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        e.scan(&PathEvt {}).unwrap();
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
        assert!(e.scan(&IpEvt {}).unwrap().is_default_exclude());

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        assert!(e.scan(&PathEvt {}).unwrap().is_only_filter_include());
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
        assert!(e.scan(&IpEvt {}).unwrap().is_default_exclude());

        // if not explicitely excluded it is included
        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        assert!(e.scan(&PathEvt {}).unwrap().filter_decision().is_include());

        fake_event!(DnsEvt, id = 3, source = "test", (".domain", "test.com"));
        assert!(e.scan(&DnsEvt {}).unwrap().filter_decision().is_include());
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
        assert!(e.scan(&IpEvt {}).unwrap().is_default_exclude());

        fake_event!(PathEvt, id = 2, source = "test", (".path", "/bin/ls"));
        assert!(e.scan(&PathEvt {}).unwrap().filter_decision().is_include());

        // this has not been excluded but not included so it should
        // not match
        fake_event!(DnsEvt, id = 3, source = "test", (".domain", "test.com"));
        assert!(e.scan(&DnsEvt {}).unwrap().is_default_exclude());
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
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("match"));
        assert!(sr.includes_action("do_something"));
        assert!(sr.filter_decision().is_include());
        assert!(!sr.is_only_filter_include());
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
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("test.1"));
        assert!(sr.includes_detection("test.2"));
        assert!(sr.includes_tag("some:random:tag"));
        assert!(sr.includes_tag("another:tag"));
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
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("detect.t4242"));
        assert!(sr.includes_detection("detect.t4343"));
        assert!(sr.includes_attack_id("t4242"));
        assert!(sr.includes_attack_id("t4343"));
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
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("main"));
        assert!(!sr.includes_detection("dep.rule"));
        assert!(sr.includes_detection("match.all"));

        fake_event!(Dummy2, id = 1, source = "test", (".ip", "8.8.8.8"));
        let sr = e.scan(&Dummy2 {}).unwrap();
        assert!(!sr.includes_detection("depends"));
        assert!(!sr.includes_detection("dep.rule"));
        assert!(sr.includes_detection("match.all"));
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

    #[test]
    fn test_rule_dependency_bug() {
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
name: dep.rule
type: dependency
match-on:
    events:
        test: [ 1 ]
matches:
    $ip: .ipv6 == '::1'
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

        fake_event!(Dummy, id = 1, source = "test", (".ipv6", "::1"));
        let sr = e.scan(&Dummy {}).unwrap();
        assert!(sr.includes_detection("main"));
        assert!(!sr.includes_detection("dep.rule"));
        assert!(sr.includes_detection("match.all"));

        fake_event!(Dummy2, id = 2, source = "test", (".ip", "8.8.8.8"));
        let sr = e.scan(&Dummy2 {}).unwrap();
        assert!(!sr.includes_detection("depends"));
        assert!(!sr.includes_detection("dep.rule"));
        assert!(sr.includes_detection("match.all"));
    }

    #[test]
    fn test_decision_include_behavior() {
        // Test basic include decision behavior
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
    name: include.rule
    matches:
        $a: .ip == "8.8.4.4"
    condition: $a
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(TestEvent, id = 1, source = "test", (".ip", "8.8.4.4"));

        let sr = e.scan(&TestEvent {}).unwrap();
        assert!(sr.includes_detection("include.rule"));
        assert!(sr.detection_decision().is_include());
    }

    #[test]
    fn test_decision_exclude_behavior() {
        // Test basic exclude decision behavior
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
    name: exclude.rule
    decision: exclude
    matches:
        $a: .ip == "8.8.4.4"
    condition: $a
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();
        fake_event!(TestEvent, id = 1, source = "test", (".ip", "8.8.4.4"));

        let sr = e.scan(&TestEvent {}).unwrap();
        assert!(!sr.is_default_exclude());
        assert!(sr.detection_decision().is_exclude());
    }

    #[test]
    fn test_decision_exclude_stops_processing() {
        // Test that exclude decisions stop further rule processing
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: first.rule
matches:
    $a: .field == "value"
condition: $a

---
name: exclude.rule
decision: exclude
matches:
    $b: .other == "trigger"
condition: $b

---
name: third.rule
matches:
    $c: .another == "should_not_match"
condition: $c
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(
            TestEvent,
            id = 1,
            source = "test",
            (".field", "value"),
            (".other", "trigger"),
            (".another", "should_not_match")
        );

        let sr = e.scan(&TestEvent {}).unwrap();
        assert!(!sr.includes_detection("first.rule"));
        assert!(!sr.includes_detection("exclude.rule"));
        assert!(!sr.includes_detection("third.rule"));
        assert!(sr.detection_decision().is_exclude())
    }

    #[test]
    fn test_decision_include_continues_processing() {
        // Test that include decisions allow all rules to process
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: first.rule
matches:
    $a: .field == "value"
condition: $a

---
name: second.rule
matches:
    $b: .other == "trigger"
condition: $b

---
name: third.rule
matches:
    $c: .another == "match"
condition: $c
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(
            TestEvent,
            id = 1,
            source = "test",
            (".field", "value"),
            (".other", "trigger"),
            (".another", "match")
        );

        let sr = e.scan(&TestEvent {}).unwrap();
        assert!(sr.includes_detection("first.rule"));
        assert!(sr.includes_detection("second.rule"));
        assert!(sr.includes_detection("third.rule"));
        assert!(sr.detection_decision().is_include())
    }

    #[test]
    fn test_decision_mixed_scenarios_1() {
        // Test mixed include/exclude scenarios
        // Both detection and filter should be included
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: filter.rule
type: filter
matches:
    $a: .field == "value"
condition: $a

---
name: detection.rule
matches:
    $b: .other == "trigger"
condition: $b
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(
            TestEvent,
            id = 1,
            source = "test",
            (".field", "value"),
            (".other", "trigger")
        );

        let sr = e.scan(&TestEvent {}).unwrap();
        assert!(sr.includes_filter("filter.rule"));
        assert!(sr.includes_detection("detection.rule"));
        assert!(sr.filter_decision().is_include());
        assert!(sr.detection_decision().is_include());
    }

    #[test]
    fn test_decision_mixed_scenarios_2() {
        // Test mixed include/exclude scenarios where
        // we exclude event in a filter but a detection
        // might include it too.
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: filter.rule
type: filter
decision: exclude
matches:
    $a: .field == "value"
condition: $a

---
name: detection.rule
matches:
    $b: .other == "trigger"
condition: $b
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(
            TestEvent,
            id = 1,
            source = "test",
            (".field", "value"),
            (".other", "trigger")
        );

        let sr = e.scan(&TestEvent {}).unwrap();
        // filter must exclude
        assert!(!sr.includes_filter("filter.rule"));
        assert!(sr.filter_decision().is_exclude());

        // detection must include
        assert!(sr.includes_detection("detection.rule"));
        assert!(sr.detection_decision().is_include());
    }

    #[test]
    fn test_decision_mixed_scenarios_3() {
        // Test mixed include/exclude scenarios where
        // we exclude event in adetection but a filter
        // includes it.
        let mut c = Compiler::new();
        c.load_rules_from_str(
            r#"
---
name: filter.rule
type: filter
matches:
    $a: .field == "value"
condition: $a

---
name: detection.rule
decision: exclude
matches:
    $b: .other == "trigger"
condition: $b
    "#,
        )
        .unwrap();

        let mut e = Engine::try_from(c).unwrap();

        fake_event!(
            TestEvent,
            id = 1,
            source = "test",
            (".field", "value"),
            (".other", "trigger")
        );

        let sr = e.scan(&TestEvent {}).unwrap();
        // filter must include
        assert!(sr.includes_filter("filter.rule"));
        assert!(sr.filter_decision().is_include());

        // detection must exclude
        assert!(!sr.includes_detection("detection.rule"));
        assert!(sr.detection_decision().is_exclude());
    }
}
