use std::str::FromStr;

use pest::{
    error::ErrorVariant,
    iterators::{Pair, Pairs},
    Parser, Span,
};
use pest_derive::Parser;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::{
    engine::ScanContext,
    rules,
    values::{Number, NumberError},
    Event, FieldValue,
};

use crate::paths::{PathError, XPath};

#[derive(Parser)]
#[grammar = "rules/grammars/match.pest"]
pub(crate) struct MatchParser;

impl MatchParser {
    #[inline]
    pub(crate) fn parse_path_segments(
        pairs: Pairs<Rule>,
    ) -> Result<Vec<String>, Box<pest::error::Error<Rule>>> {
        fn _parse_segments(mut pairs: Pairs<Rule>, segments: &mut Vec<String>) {
            if let Some(next) = pairs.next() {
                match next.as_rule() {
                    Rule::field_path => _parse_segments(next.into_inner(), segments),
                    Rule::segment | Rule::segment_with_ws => {
                        segments.push(next.as_str().into());
                        if let Some(next) = pairs.next() {
                            _parse_segments(next.into_inner(), segments)
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut segments = vec![];
        _parse_segments(pairs, &mut segments);
        Ok(segments)
    }

    pub(crate) fn parse_path<S: AsRef<str>>(
        s: S,
    ) -> Result<Vec<String>, Box<pest::error::Error<Rule>>> {
        let pairs = MatchParser::parse(Rule::field_path, s.as_ref())?;
        Self::parse_path_segments(pairs)
    }

    #[inline]
    fn parse_input<S: AsRef<str>>(input: S) -> Result<Match, ParseError> {
        let mut pairs = MatchParser::parse(Rule::matcher, input.as_ref()).map_err(Box::new)?;
        match pairs.next() {
            Some(pair) => {
                let span = pair.as_span();
                match pair.into_inner().next() {
                    Some(pair) => match pair.as_rule() {
                        Rule::direct_match => {
                            DirectMatch::from_str(input.as_ref()).map(Match::from)
                        }
                        Rule::indirect_match => {
                            IndirectMatch::from_str(input.as_ref()).map(Match::from)
                        }
                        Rule::rule_match => Ok(Match::from(RuleMatch::from_pair(pair))),
                        _ => Err(ParseError::new("unknown match format", pair.as_span())),
                    },
                    _ => Err(ParseError::new("match empty inner pairs", span)),
                }
            }
            _ => unreachable!(),
        }
    }
}

/// MatchValue is an enum of representing a value we want
/// a rule to match
#[derive(Debug, Clone)]
pub(crate) enum MatchValue {
    String(String),
    Number(Number),
    StringOrNumber(String, Number),
    Regex(Regex),
    Bool(bool),
    Some,
    None,
}

impl MatchValue {
    const fn type_str(&self) -> &'static str {
        match self {
            Self::String(_) => "string",
            Self::Number(_) => "number",
            Self::StringOrNumber(_, _) => "string_or_number",
            Self::Regex(_) => "regex",
            Self::Bool(_) => "bool",
            Self::Some => "some",
            Self::None => "none",
        }
    }

    const fn is_number(&self) -> bool {
        matches!(self, MatchValue::Number(_))
    }
}

/// Error raised while parsing a match expression.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParseError {
    /// Invalid field path.
    #[error("{0}")]
    Path(#[from] PathError),
    /// Syntax error in the match expression.
    #[error("{0}")]
    Parser(#[from] Box<pest::error::Error<Rule>>),
    /// Invalid number value.
    #[error("{0}")]
    ParseNum(#[from] NumberError),
    /// Invalid regular expression.
    #[error("{0}")]
    Regex(#[from] regex::Error),
}

impl ParseError {
    #[inline]
    fn new<S: ToString>(msg: S, span: Span<'_>) -> Self {
        Self::Parser(Box::new(pest::error::Error::new_from_span(
            ErrorVariant::CustomError {
                message: msg.to_string(),
            },
            span,
        )))
    }
}

/// Error raised while matching an event.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum Error {
    /// A `rule(name)` operand references a rule unknown to the engine.
    #[error("dependency rule={0} not found")]
    DependencyNotFound(String),
    /// A `rule(name)` operand was evaluated outside of an engine scan.
    #[error("dependency rule={0} cannot be resolved without an engine")]
    DependencyUnresolved(String),
    /// The event has no field at this path.
    #[error("field={0} not found")]
    FieldNotFound(String),
    /// The event field's type doesn't match the value in the rule.
    #[error("incompatible types field={path} expect={expect} got={got}")]
    IncompatibleTypes {
        /// Path of the field.
        path: String,
        /// Type expected by the rule.
        expect: &'static str,
        /// Type of the event field.
        got: &'static str,
    },
    /// A dependency failed; wraps its error.
    #[error("dependency: {0}")]
    Rule(Box<rules::Error>),
}

impl From<rules::Error> for Error {
    fn from(value: rules::Error) -> Self {
        Self::Rule(Box::new(value))
    }
}

impl Error {
    #[inline]
    pub(crate) fn dependency_not_found<S: AsRef<str>>(s: S) -> Self {
        Self::DependencyNotFound(s.as_ref().into())
    }
}

impl MatchValue {
    fn value_regex(s: &str, is_case_insensitive: bool) -> Result<Self, ParseError> {
        RegexBuilder::new(s)
            .case_insensitive(is_case_insensitive)
            .build()
            .map(Self::Regex)
            .map_err(|e| e.into())
    }

    fn value_number<S: AsRef<str>>(s: S) -> Result<Self, ParseError> {
        let s = s.as_ref();
        Ok(MatchValue::Number(Number::from_str(s)?))
    }
}

/// All match variants that can be used to match logs
#[derive(Debug, Clone)]
pub(crate) enum Match {
    Direct(DirectMatch),
    Indirect(IndirectMatch),
    Rule(RuleMatch),
}

impl Match {
    /// Rough relative evaluation cost, used to evaluate cheap operands first.
    pub(crate) const fn cost(&self) -> u8 {
        match self {
            // scans the whole field, unlike equality
            Self::Direct(d) if matches!(d.op, Op::Contains | Op::IContains) => 2,
            Self::Direct(d) => match d.value {
                MatchValue::Bool(_)
                | MatchValue::Number(_)
                | MatchValue::Some
                | MatchValue::None => 0,
                MatchValue::String(_) | MatchValue::StringOrNumber(..) => 1,
                MatchValue::Regex(_) => 3,
            },
            Self::Indirect(_) => 2,
            Self::Rule(_) => 4,
        }
    }
}

impl From<IndirectMatch> for Match {
    fn from(value: IndirectMatch) -> Self {
        Self::Indirect(value)
    }
}

impl From<DirectMatch> for Match {
    fn from(value: DirectMatch) -> Self {
        Self::Direct(value)
    }
}

impl From<RuleMatch> for Match {
    fn from(value: RuleMatch) -> Self {
        Self::Rule(value)
    }
}

impl FromStr for Match {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MatchParser::parse_input(s)
    }
}

impl Match {
    #[inline]
    pub(crate) fn match_event<E>(
        &self,
        event: &E,
        ctx: Option<&mut ScanContext<'_, E>>,
    ) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        match self {
            Self::Direct(m) => m.match_event(event),
            Self::Indirect(m) => m.match_event(event),
            Self::Rule(m) => m.match_event(ctx),
        }
    }
}

// Indirect Match implementation

#[derive(Debug, Clone)]
pub(crate) struct IndirectMatch {
    field_path: XPath,
    other_field: XPath,
}

impl FromStr for IndirectMatch {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut pairs = MatchParser::parse(Rule::indirect_match, s).map_err(Box::new)?;
        let mut inner_pairs = pairs.next().unwrap().into_inner();

        // the code should not panic here as everything got validated by the parser
        let first = inner_pairs
            .find(|p| matches!(p.as_rule(), Rule::field_path))
            .unwrap();

        //
        let second = inner_pairs
            .find(|p| matches!(p.as_rule(), Rule::indirect_field_path))
            .unwrap();

        Ok(Self {
            field_path: XPath::from_str(first.as_str())?,
            // easier to trim @ than walking through the parsed data
            other_field: XPath::from_str(second.as_str().trim_start_matches('@'))?,
        })
    }
}

impl IndirectMatch {
    pub(crate) fn match_event<E>(&self, event: &E) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        let src = event
            .get_from_path(&self.field_path)
            .ok_or(Error::FieldNotFound(
                self.field_path.to_string_lossy().into(),
            ))?;

        let tgt = event
            .get_from_path(&self.other_field)
            .ok_or(Error::FieldNotFound(
                self.other_field.to_string_lossy().into(),
            ))?;

        Ok(src == tgt)
    }
}

// Direct Match implementation

/// Enum used to describe the match operator of [DirectMatch]
#[derive(Debug, Clone, Copy)]
enum Op {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    Rex,
    IRex,
    Flag,
    IEq,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
}

impl Op {
    fn from_pair(pair: Pair<'_, Rule>) -> Self {
        match pair.as_rule() {
            Rule::eq => Op::Eq,
            Rule::lte => Op::Lte,
            Rule::lt => Op::Lt,
            Rule::gte => Op::Gte,
            Rule::gt => Op::Gt,
            Rule::rex => Op::Rex,
            Rule::irex => Op::IRex,
            Rule::flag => Op::Flag,
            Rule::ieq => Op::IEq,
            Rule::contains => Op::Contains,
            Rule::icontains => Op::IContains,
            Rule::startswith => Op::StartsWith,
            Rule::istartswith => Op::IStartsWith,
            Rule::endswith => Op::EndsWith,
            Rule::iendswith => Op::IEndsWith,
            // cannot be something else
            _ => unreachable!(),
        }
    }
}

/// DirectMatch represensts the needed information to perform a matching
/// operation on a log field
#[derive(Debug, Clone)]
pub(crate) struct DirectMatch {
    field_path: XPath,
    op: Op,
    value: MatchValue,
}

impl MatchValue {
    fn from_pair(op: Op, pair: Pair<'_, Rule>) -> Result<Self, ParseError> {
        debug_assert!(matches!(
            pair.as_rule(),
            Rule::eq_value | Rule::numeric_value | Rule::string_value
        ));

        // this cannot panic as value must have at least one inner pair
        let inner_pair = pair.into_inner().next().unwrap();
        let span = inner_pair.as_span();

        match op {
            Op::Eq => match inner_pair.as_rule() {
                Rule::number | Rule::hex => {
                    let num_str = inner_pair.as_str().trim_matches('\'').trim_matches('"');
                    Ok(MatchValue::StringOrNumber(
                        num_str.into(),
                        Number::from_str(num_str)?,
                    ))
                }
                Rule::value_dq => Ok(MatchValue::String(
                    inner_pair.as_str().trim_matches('"').into(),
                )),
                Rule::value_sq => Ok(MatchValue::String(
                    inner_pair.as_str().trim_matches('\'').into(),
                )),
                Rule::none => Ok(MatchValue::None),
                Rule::some => Ok(MatchValue::Some),
                Rule::bool_true => Ok(MatchValue::Bool(true)),
                Rule::bool_false => Ok(MatchValue::Bool(false)),
                _ => {
                    unreachable!()
                }
            },
            Op::Lt | Op::Lte | Op::Gt | Op::Gte | Op::Flag => {
                let num_str = inner_pair.as_str().trim_matches('\'').trim_matches('"');
                match MatchValue::value_number(num_str)? {
                    // we cannot &= on float
                    MatchValue::Number(Number::Float(_)) if matches!(op, Op::Flag) => {
                        Err(ParseError::new("value must be an integer", span))
                    }
                    v => Ok(v),
                }
            }
            Op::Rex | Op::IRex => {
                let is_case_insensitive = matches!(op, Op::IRex);
                match inner_pair.as_rule() {
                    Rule::value_dq => MatchValue::value_regex(
                        inner_pair.as_str().trim_matches('"'),
                        is_case_insensitive,
                    ),
                    Rule::value_sq => MatchValue::value_regex(
                        inner_pair.as_str().trim_matches('\''),
                        is_case_insensitive,
                    ),
                    // the grammar only allows quoted strings
                    _ => unreachable!(),
                }
            }
            Op::IEq
            | Op::Contains
            | Op::IContains
            | Op::StartsWith
            | Op::IStartsWith
            | Op::EndsWith
            | Op::IEndsWith => {
                let value = match inner_pair.as_rule() {
                    Rule::value_dq => inner_pair.as_str().trim_matches('"'),
                    Rule::value_sq => inner_pair.as_str().trim_matches('\''),
                    // the grammar only allows quoted strings
                    _ => unreachable!(),
                };
                // an empty search value would match any string
                if value.is_empty() && !matches!(op, Op::IEq) {
                    return Err(ParseError::new("value must not be empty", span));
                }
                // these operators fold ASCII only, a non-ASCII cased letter would silently stay case-sensitive
                let is_ascii_folding = matches!(
                    op,
                    Op::IEq | Op::IContains | Op::IStartsWith | Op::IEndsWith
                );
                let has_non_ascii_cased_letter = value
                    .chars()
                    .any(|c| !c.is_ascii() && (c.is_uppercase() || c.is_lowercase()));
                if is_ascii_folding && has_non_ascii_cased_letter {
                    return Err(ParseError::new(
                        "value must not contain non-ASCII cased letters, use imatches instead",
                        span,
                    ));
                }
                Ok(MatchValue::String(value.into()))
            }
        }
    }
}

impl FromStr for DirectMatch {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pairs = MatchParser::parse(Rule::_direct_match, s).map_err(Box::new)?;

        let mut op = None;
        let mut field_path = None;
        let mut value = None;

        for pair in pairs {
            match pair.as_rule() {
                Rule::field_path => {
                    field_path = Some(XPath::parse(pair.as_str())?);
                }
                Rule::eq_value | Rule::numeric_value | Rule::string_value => {
                    value = Some(MatchValue::from_pair(op.unwrap(), pair)?)
                }
                Rule::EOI => {}
                // the grammar only leaves operators
                _ => op = Some(Op::from_pair(pair)),
            }
        }

        // parser guarantees those values are available
        let m = DirectMatch {
            field_path: field_path.unwrap(),
            op: op.unwrap(),
            value: value.unwrap(),
        };

        Ok(m)
    }
}

macro_rules! cmp_values {
    ($variant:tt, $value:expr, $op:tt, $other:expr) => {
        if let ($crate::FieldValue::$variant(v), MatchValue::$variant(o)) = (&$value, &$other) {
            Ok(v $op o)
        } else {
            Err(())
        }
    };
}

impl DirectMatch {
    #[inline]
    pub(crate) fn match_event<E>(&self, event: &E) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        if let Some(fvalue) = event.get_from_path(&self.field_path) {
            return self
                .match_value(&fvalue)
                .map_err(|_| Error::IncompatibleTypes {
                    path: self.field_path.to_string_lossy().into(),
                    expect: self.value.type_str(),
                    got: fvalue.type_str(),
                });
        }
        Err(Error::FieldNotFound(
            self.field_path.to_string_lossy().into(),
        ))
    }

    #[inline]
    pub(crate) fn match_value(&self, tgt: &FieldValue) -> Result<bool, ()> {
        // we handle a special case where we expect to match a number and the field is a string
        // in this case we attempt to convert the string value into a number. Mostly because
        // de/serializing hexadecimal values provides more readable output using strings.
        let compat = {
            if tgt.is_string() && self.value.is_number() {
                Some(tgt.string_into_number().map_err(|_| ())?)
            } else {
                None
            }
        };

        let fv = compat.as_ref().unwrap_or(tgt);

        if let FieldValue::Vector(v) = fv {
            for fv in v.iter() {
                if self.match_value(fv)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        }

        match self.op {
            Op::Eq => cmp_values!(String, fv, ==, self.value)
                .or({
                    if let (FieldValue::None, MatchValue::None) = (&fv, &(self.value)) {
                        Ok(true)
                    } else {
                        Err(())
                    }
                })
                .or(
                    if let (FieldValue::String(s), MatchValue::StringOrNumber(v, _)) =
                        (&fv, &(self.value))
                    {
                        Ok(s == v)
                    } else {
                        Err(())
                    },
                )
                .or(
                    if let (FieldValue::Number(n), MatchValue::StringOrNumber(_, v)) =
                        (&fv, &(self.value))
                    {
                        Ok(n == v)
                    } else {
                        Err(())
                    },
                )
                .or(
                    if let (FieldValue::Bool(fvb), MatchValue::Bool(mvb)) = (&fv, &(self.value)) {
                        Ok(fvb == mvb)
                    } else {
                        Err(())
                    },
                )
                .or(
                    // we return Ok only if we want to match some
                    if matches!(self.value, MatchValue::Some) {
                        Ok(fv.is_some())
                    } else {
                        Err(())
                    },
                ),
            Op::Gt => cmp_values!(Number, fv, >, self.value),
            Op::Gte => cmp_values!(Number, fv, >=, self.value),
            Op::Lt => cmp_values!(Number, fv, <, self.value),
            Op::Lte => cmp_values!(Number, fv, <=, self.value),
            Op::Flag => {
                if let (MatchValue::Number(v), FieldValue::Number(o)) = (&(self.value), &fv) {
                    // rule & field == rule
                    v.checked_bitand(*o).map(|r| r == *v).ok_or(())
                } else {
                    Err(())
                }
            }
            Op::Rex | Op::IRex => {
                if let (MatchValue::Regex(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(v.is_match(o))
                } else {
                    Err(())
                }
            }
            Op::IEq => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(o.eq_ignore_ascii_case(v))
                } else {
                    Err(())
                }
            }
            Op::Contains => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(o.contains(v.as_str()))
                } else {
                    Err(())
                }
            }
            Op::IContains => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    // the parser rejects empty values, so windows() cannot panic on 0
                    Ok(o.as_bytes()
                        .windows(v.len())
                        .any(|window| window.eq_ignore_ascii_case(v.as_bytes())))
                } else {
                    Err(())
                }
            }
            Op::StartsWith => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(o.starts_with(v.as_str()))
                } else {
                    Err(())
                }
            }
            Op::IStartsWith => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    // bytes, not str: slicing a str inside a multi-byte character panics
                    Ok(o.len() >= v.len()
                        && o.as_bytes()[..v.len()].eq_ignore_ascii_case(v.as_bytes()))
                } else {
                    Err(())
                }
            }
            Op::EndsWith => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(o.ends_with(v.as_str()))
                } else {
                    Err(())
                }
            }
            Op::IEndsWith => {
                if let (MatchValue::String(v), FieldValue::String(o)) = (&self.value, &fv) {
                    // bytes, not str: slicing a str inside a multi-byte character panics
                    Ok(o.len() >= v.len()
                        && o.as_bytes()[o.len() - v.len()..].eq_ignore_ascii_case(v.as_bytes()))
                } else {
                    Err(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Reference to another rule's result: the rule name, and its index in the
/// engine, set on insertion.
pub(crate) struct RuleMatch(String, Option<usize>);

impl RuleMatch {
    #[inline]
    fn from_pair(pair: Pair<'_, Rule>) -> Self {
        debug_assert_eq!(pair.as_rule(), Rule::rule_match);
        let mut out = None;
        for pair in pair.into_inner() {
            match pair.as_rule() {
                Rule::rule_name => out = Some(RuleMatch(pair.as_str().into(), None)),
                // grammar doesn't allow anything else
                _ => unreachable!(),
            }
        }
        out.unwrap()
    }

    #[inline]
    pub(crate) fn match_event<E>(&self, ctx: Option<&mut ScanContext<'_, E>>) -> Result<bool, Error>
    where
        E: for<'e> Event<'e>,
    {
        match (ctx, self.1) {
            (Some(ctx), Some(i)) => Ok(ctx.match_rule_at(i)?),
            (Some(_), None) => {
                debug_assert!(false, "dependency {} not bound by the engine", self.0);
                Err(Error::dependency_not_found(&self.0))
            }
            (None, _) => Err(Error::DependencyUnresolved(self.0.clone())),
        }
    }

    #[inline]
    pub(crate) fn rule_name(&self) -> &str {
        &self.0
    }

    #[inline]
    pub(crate) fn set_rule_index(&mut self, i: usize) {
        self.1 = Some(i);
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_direct_match() {
        let dm = DirectMatch::from_str(r#".data.exe.file == "ba ba C:\windows\test\w""#).unwrap();

        assert_eq!(dm.field_path.to_string_lossy(), ".data.exe.file");
        assert_eq!(dm.field_path.segments()[0], "data");
        assert_eq!(dm.field_path.segments()[1], "exe");
        assert_eq!(dm.field_path.segments()[2], "file");

        assert!(DirectMatch::from_str(r#".data.exe.size == none"#)
            .unwrap()
            .match_value(&FieldValue::None)
            .unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.size >= '42'"#)
            .unwrap()
            .match_value(&43.into())
            .unwrap());

        // should work without quotes too
        assert!(DirectMatch::from_str(r#".data.exe.size >= 42"#)
            .unwrap()
            .match_value(&43.into())
            .unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.size > '42'"#)
            .unwrap()
            .match_value(&43.into())
            .unwrap());

        // should work without quotes too
        assert!(DirectMatch::from_str(r#".data.exe.size > 42"#)
            .unwrap()
            .match_value(&43.into())
            .unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.size &= '0x40'"#)
            .unwrap()
            .match_value(&0x100040.into())
            .unwrap());

        // should work without quotes too
        assert!(DirectMatch::from_str(r#".data.exe.size &= 0x40"#)
            .inspect_err(|e| println!("{e}"))
            .unwrap()
            .match_value(&0x100040.into())
            .unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.size ~= 'toast'"#)
            .unwrap()
            .match_value(&"toast".into())
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is none"#)
            .unwrap()
            .match_value(&FieldValue::None)
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is some"#)
            .unwrap()
            .match_value(&FieldValue::Some)
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is some"#)
            .unwrap()
            .match_value(&FieldValue::Number(42.into()))
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is some"#)
            .unwrap()
            .match_value(&FieldValue::String("hello world".into()))
            .unwrap());

        assert!(!DirectMatch::from_str(r#".data is some"#)
            .unwrap()
            .match_value(&FieldValue::None)
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is true"#)
            .unwrap()
            .match_value(&FieldValue::Bool(true))
            .unwrap());

        assert!(DirectMatch::from_str(r#".data is false"#)
            .unwrap()
            .match_value(&FieldValue::Bool(false))
            .unwrap());

        // we try to match None against a string so we must return an error
        assert!(DirectMatch::from_str(r#".data is 'toast'"#)
            .unwrap()
            .match_value(&FieldValue::None)
            .is_err());
    }

    #[test]
    fn test_matches_is_regex_operator() {
        let dm = DirectMatch::from_str(r#".data.exe.path matches '(?i)/bash$'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/BASH".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash.sh".into()).unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.path matches 42"#).is_err());
    }

    #[test]
    fn test_imatches_is_case_insensitive_regex_operator() {
        let dm = DirectMatch::from_str(r#".data.exe.path imatches '/bash$'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/BASH".into()).unwrap());
        assert!(dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash.sh".into()).unwrap());

        let dm = DirectMatch::from_str(r#".data.exe.path matches '/bash$'"#).unwrap();
        assert!(!dm.match_value(&"/usr/bin/BASH".into()).unwrap());

        assert!(DirectMatch::from_str(r#".data.exe.path imatches 42"#).is_err());
    }

    fn assert_parses(op: &str, values: &[&str]) {
        for value in values {
            let rule = format!(".data.field {op} {value}");
            assert!(DirectMatch::from_str(&rule).is_ok(), "{rule} must parse");
        }
    }

    fn assert_rejects(op: &str, values: &[&str]) {
        for value in values {
            let rule = format!(".data.field {op} {value}");
            assert!(
                DirectMatch::from_str(&rule).is_err(),
                "{rule} must not parse"
            );
        }
    }

    #[test]
    fn test_eq_accepted_values() {
        for op in ["==", "is"] {
            assert_parses(
                op,
                &[
                    "none", "some", "true", "false", "42", "'42'", "\"42\"", "4.2", "0x40",
                    "'0x40'", "'dead'", "'text'", "\"text\"", "''",
                ],
            );
            assert_rejects(op, &["text"]);
        }
    }

    #[test]
    fn test_comparison_accepted_values() {
        for op in ["<", "<=", ">", ">="] {
            assert_parses(op, &["42", "'42'", "\"42\"", "4.2", "0x40", "'0x40'"]);
            assert_rejects(
                op,
                &["none", "some", "true", "false", "'text'", "\"text\"", "''"],
            );
        }
    }

    #[test]
    fn test_flag_accepted_values() {
        assert_parses("&=", &["64", "'64'", "0x40", "'0x40'"]);
        assert_rejects("&=", &["4.2", "none", "some", "true", "false", "'text'"]);
    }

    #[test]
    fn test_regex_accepted_values() {
        for op in ["~=", "matches", "imatches"] {
            assert_parses(
                op,
                &["'text'", "\"text\"", "''", "'123'", "\"123\"", "'dead'"],
            );
            assert_rejects(op, &["none", "some", "true", "false", "42", "0x40", "dead"]);
        }
    }

    #[test]
    fn test_regex_quoted_number_and_hex_are_text() {
        let dm = DirectMatch::from_str(r#".data.field matches '123'"#).unwrap();
        assert!(dm.match_value(&"a123b".into()).unwrap());

        let dm = DirectMatch::from_str(r#".data.field imatches 'dead'"#).unwrap();
        assert!(dm.match_value(&"0xDEADBEEF".into()).unwrap());
    }

    #[test]
    fn test_iequals_accepted_values() {
        assert_parses(
            "iequals",
            &["'text'", "\"text\"", "''", "'123'", "\"123\"", "'0x40'"],
        );
        assert_rejects(
            "iequals",
            &["none", "some", "true", "false", "42", "0x40", "text"],
        );
    }

    #[test]
    fn test_iequals_is_ascii_case_insensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path iequals '/usr/bin/Bash'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(dm.match_value(&"/USR/BIN/BASH".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash.sh".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bas".into()).unwrap());
    }

    #[test]
    fn test_iequals_quoted_number_and_hex_are_text() {
        let dm = DirectMatch::from_str(r#".data.field iequals '123'"#).unwrap();
        assert!(dm.match_value(&"123".into()).unwrap());
        assert!(!dm.match_value(&"0123".into()).unwrap());

        let dm = DirectMatch::from_str(r#".data.field iequals '0xDEAD'"#).unwrap();
        assert!(dm.match_value(&"0xdead".into()).unwrap());
        assert!(!dm.match_value(&"57005".into()).unwrap());
    }

    #[test]
    fn test_iequals_empty_value_matches_empty_field() {
        let dm = DirectMatch::from_str(r#".data.field iequals ''"#).unwrap();
        assert!(dm.match_value(&"".into()).unwrap());
        assert!(!dm.match_value(&"a".into()).unwrap());
    }

    #[test]
    fn test_iequals_vector_field() {
        let dm = DirectMatch::from_str(r#".data.field iequals 'bash'"#).unwrap();
        let field = FieldValue::Vector(vec!["sh".into(), "BASH".into()]);
        assert!(dm.match_value(&field).unwrap());
        let field = FieldValue::Vector(vec!["sh".into(), "zsh".into()]);
        assert!(!dm.match_value(&field).unwrap());
    }

    #[test]
    fn test_iequals_non_string_field_is_error() {
        let dm = DirectMatch::from_str(r#".data.field iequals '42'"#).unwrap();
        assert!(dm.match_value(&42.into()).is_err());
        assert!(dm.match_value(&FieldValue::Bool(true)).is_err());
        assert!(dm.match_value(&FieldValue::None).is_err());
    }

    #[test]
    fn test_contains_accepted_values() {
        for op in ["contains", "icontains"] {
            assert_parses(op, &["'text'", "\"text\"", "'123'", "\"123\"", "'0x40'"]);
            // an empty value would always match
            assert_rejects(
                op,
                &[
                    "none", "some", "true", "false", "42", "0x40", "text", "''", "\"\"",
                ],
            );
        }
    }

    #[test]
    fn test_contains_is_case_sensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path contains 'bin/Ba'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/Bash".into()).unwrap());
        assert!(dm.match_value(&"bin/Ba".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(!dm.match_value(&"bin".into()).unwrap());

        let dm = DirectMatch::from_str(r#".data.field contains 'é'"#).unwrap();
        assert!(dm.match_value(&"café crème".into()).unwrap());
    }

    #[test]
    fn test_icontains_is_ascii_case_insensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path icontains 'bin/Ba'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(dm.match_value(&"/USR/BIN/BASH".into()).unwrap());
        assert!(dm.match_value(&"BIN/ba".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/zsh".into()).unwrap());
        assert!(!dm.match_value(&"bin".into()).unwrap());
    }

    #[test]
    fn test_contains_quoted_number_and_hex_are_text() {
        for op in ["contains", "icontains"] {
            let dm = DirectMatch::from_str(&format!(".data.field {op} '123'")).unwrap();
            assert!(dm.match_value(&"a123b".into()).unwrap());
            assert!(!dm.match_value(&"a12b".into()).unwrap());

            let dm = DirectMatch::from_str(&format!(".data.field {op} '0x40'")).unwrap();
            assert!(dm.match_value(&"flags=0x40".into()).unwrap());
            assert!(!dm.match_value(&"64".into()).unwrap());
        }
    }

    #[test]
    fn test_contains_vector_field() {
        for op in ["contains", "icontains"] {
            let dm = DirectMatch::from_str(&format!(".data.field {op} 'bash'")).unwrap();
            let field = FieldValue::Vector(vec!["sh".into(), "/bin/bash".into()]);
            assert!(dm.match_value(&field).unwrap());
            let field = FieldValue::Vector(vec!["sh".into(), "zsh".into()]);
            assert!(!dm.match_value(&field).unwrap());
        }
    }

    #[test]
    fn test_contains_non_string_field_is_error() {
        for op in ["contains", "icontains"] {
            let dm = DirectMatch::from_str(&format!(".data.field {op} '42'")).unwrap();
            assert!(dm.match_value(&42.into()).is_err());
            assert!(dm.match_value(&FieldValue::Bool(true)).is_err());
            assert!(dm.match_value(&FieldValue::None).is_err());
        }
    }

    const PREFIX_SUFFIX_OPS: [&str; 4] = ["startswith", "istartswith", "endswith", "iendswith"];

    #[test]
    fn test_startswith_endswith_accepted_values() {
        for op in PREFIX_SUFFIX_OPS {
            assert_parses(op, &["'text'", "\"text\"", "'123'", "\"123\"", "'0x40'"]);
            // an empty value would always match
            assert_rejects(
                op,
                &[
                    "none", "some", "true", "false", "42", "0x40", "text", "''", "\"\"",
                ],
            );
        }
    }

    #[test]
    fn test_istartswith_is_not_read_as_is_operator() {
        let dm = DirectMatch::from_str(r#".data.field istartswith 'x'"#).unwrap();
        assert!(dm.match_value(&"Xyz".into()).unwrap());
    }

    #[test]
    fn test_startswith_is_case_sensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path startswith '/usr/Bin'"#).unwrap();
        assert!(dm.match_value(&"/usr/Bin/bash".into()).unwrap());
        assert!(dm.match_value(&"/usr/Bin".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(!dm.match_value(&"/bin/usr/Bin".into()).unwrap());
        assert!(!dm.match_value(&"/usr".into()).unwrap());

        let dm = DirectMatch::from_str(r#".data.field startswith 'é'"#).unwrap();
        assert!(dm.match_value(&"été".into()).unwrap());
    }

    #[test]
    fn test_istartswith_is_ascii_case_insensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path istartswith '/usr/Bin'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(dm.match_value(&"/USR/BIN/BASH".into()).unwrap());
        assert!(dm.match_value(&"/USR/bin".into()).unwrap());
        assert!(!dm.match_value(&"/bin/usr/bin".into()).unwrap());
        assert!(!dm.match_value(&"/usr".into()).unwrap());

        // the pattern length falls inside a multi-byte character of the field
        let dm = DirectMatch::from_str(r#".data.field istartswith '™'"#).unwrap();
        assert!(!dm.match_value(&"a™".into()).unwrap());
    }

    #[test]
    fn test_endswith_is_case_sensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path endswith '/Bash'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/Bash".into()).unwrap());
        assert!(dm.match_value(&"/Bash".into()).unwrap());
        assert!(!dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(!dm.match_value(&"/Bash/usr".into()).unwrap());
        assert!(!dm.match_value(&"Bash".into()).unwrap());

        let dm: DirectMatch = DirectMatch::from_str(r#".data.field endswith 'é'"#).unwrap();
        assert!(dm.match_value(&"café".into()).unwrap());
    }

    #[test]
    fn test_iendswith_is_ascii_case_insensitive() {
        let dm = DirectMatch::from_str(r#".data.exe.path iendswith '/Bash'"#).unwrap();
        assert!(dm.match_value(&"/usr/bin/bash".into()).unwrap());
        assert!(dm.match_value(&"/USR/BIN/BASH".into()).unwrap());
        assert!(dm.match_value(&"/BASH".into()).unwrap());
        assert!(!dm.match_value(&"/bash/usr".into()).unwrap());
        assert!(!dm.match_value(&"bash".into()).unwrap());

        // the pattern length falls inside a multi-byte character of the field
        let dm = DirectMatch::from_str(r#".data.field iendswith 'a'"#).unwrap();
        assert!(!dm.match_value(&"aé".into()).unwrap());
    }

    const ASCII_FOLDING_OPS: [&str; 4] = ["iequals", "icontains", "istartswith", "iendswith"];

    #[test]
    fn test_ascii_folding_ops_reject_non_ascii_cased_letters() {
        for op in ASCII_FOLDING_OPS {
            assert_rejects(op, &["'É'", "\"é\"", "'café'", "'Straße'", "'Ω'"]);
            // uncased non-ASCII characters have nothing to fold
            assert_parses(op, &["'™'", "'日本'", "'😀'", "'a™'"]);
        }
    }

    #[test]
    fn test_non_ascii_cased_letter_error_points_to_imatches() {
        for op in ASCII_FOLDING_OPS {
            let error = DirectMatch::from_str(&format!(".data.field {op} 'É'")).unwrap_err();
            assert!(error.to_string().contains("imatches"), "{op}: {error}");
        }
    }

    #[test]
    fn test_case_sensitive_ops_accept_non_ascii_cased_letters() {
        for op in [
            "==",
            "contains",
            "startswith",
            "endswith",
            "matches",
            "imatches",
        ] {
            assert_parses(op, &["'É'", "'café'"]);
        }
    }

    #[test]
    fn test_startswith_endswith_quoted_number_and_hex_are_text() {
        for op in ["startswith", "istartswith"] {
            let dm = DirectMatch::from_str(&format!(".data.field {op} '123'")).unwrap();
            assert!(dm.match_value(&"123b".into()).unwrap());
            assert!(!dm.match_value(&"0123".into()).unwrap());

            let dm = DirectMatch::from_str(&format!(".data.field {op} '0x40'")).unwrap();
            assert!(dm.match_value(&"0x40=flags".into()).unwrap());
            assert!(!dm.match_value(&"64".into()).unwrap());
        }
        for op in ["endswith", "iendswith"] {
            let dm = DirectMatch::from_str(&format!(".data.field {op} '123'")).unwrap();
            assert!(dm.match_value(&"a123".into()).unwrap());
            assert!(!dm.match_value(&"1230".into()).unwrap());

            let dm = DirectMatch::from_str(&format!(".data.field {op} '0x40'")).unwrap();
            assert!(dm.match_value(&"flags=0x40".into()).unwrap());
            assert!(!dm.match_value(&"64".into()).unwrap());
        }
    }

    #[test]
    fn test_startswith_endswith_vector_field() {
        for op in PREFIX_SUFFIX_OPS {
            let dm = DirectMatch::from_str(&format!(".data.field {op} 'bash'")).unwrap();
            let field = FieldValue::Vector(vec!["sh".into(), "bash".into()]);
            assert!(dm.match_value(&field).unwrap());
            let field = FieldValue::Vector(vec!["sh".into(), "zsh".into()]);
            assert!(!dm.match_value(&field).unwrap());
        }
    }

    #[test]
    fn test_startswith_endswith_non_string_field_is_error() {
        for op in PREFIX_SUFFIX_OPS {
            let dm = DirectMatch::from_str(&format!(".data.field {op} '42'")).unwrap();
            assert!(dm.match_value(&42.into()).is_err());
            assert!(dm.match_value(&FieldValue::Bool(true)).is_err());
            assert!(dm.match_value(&FieldValue::None).is_err());
        }
    }

    fn direct_match_cost(rule: &str) -> u8 {
        Match::from(DirectMatch::from_str(rule).unwrap()).cost()
    }

    #[test]
    fn test_contains_cost_between_equality_and_regex() {
        let equality_cost = direct_match_cost(".data.field == 'x'");
        let regex_cost = direct_match_cost(".data.field matches 'x'");
        for op in ["contains", "icontains"] {
            let contains_cost = direct_match_cost(&format!(".data.field {op} 'x'"));
            assert!(equality_cost < contains_cost, "{op} must cost more than ==");
            assert!(
                contains_cost < regex_cost,
                "{op} must cost less than matches"
            );
        }
    }

    #[test]
    fn test_indirect_match() {
        let im = IndirectMatch::from_str(r#".data.exe.size == @.data."field with space""#)
            .map_err(|e| {
                println!("{e}");
                e
            })
            .unwrap();

        assert_eq!(im.field_path.to_string_lossy(), ".data.exe.size");
        assert_eq!(
            im.other_field.to_string_lossy(),
            r#".data."field with space""#
        );
        assert_eq!(im.other_field.segments()[0], "data");
        assert_eq!(im.other_field.segments()[1], "field with space");
    }

    #[test]
    fn test_parse_path() {
        let segments =
            MatchParser::parse_path(r#".data.exe.file."with whitespace"."whitespace and .""#)
                .unwrap();
        assert_eq!(segments[0], "data");
        assert_eq!(segments[1], "exe");
        assert_eq!(segments[2], "file");
        assert_eq!(segments[3], "with whitespace");
        assert_eq!(segments[4], "whitespace and .");
    }

    #[test]
    fn test_parse_rule_match() {
        fn as_rule_match(m: Match) -> RuleMatch {
            match m {
                Match::Rule(m) => m,
                _ => panic!("not a rule match"),
            }
        }

        assert_eq!(
            as_rule_match(MatchParser::parse_input("rule(test)").unwrap()),
            RuleMatch("test".into(), None)
        );

        assert_eq!(
            as_rule_match(MatchParser::parse_input("rule(blip.blop)").unwrap()),
            RuleMatch("blip.blop".into(), None)
        )
    }
}
