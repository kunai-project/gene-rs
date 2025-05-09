use std::{borrow::Cow, collections::HashMap, str::FromStr};

use pest::{iterators::Pairs, Parser};
use pest_derive::Parser;
use regex::Regex;
use thiserror::Error;

use crate::{
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
    fn parse_input<S: AsRef<str>>(input: S) -> Result<Match, Error> {
        let mut pairs = MatchParser::parse(Rule::matcher, input.as_ref()).map_err(Box::new)?;
        match pairs.next() {
            Some(pairs) => match pairs.into_inner().next() {
                Some(pairs) => match pairs.as_rule() {
                    Rule::direct_match => DirectMatch::from_str(input.as_ref()).map(Match::from),
                    Rule::indirect_match => {
                        IndirectMatch::from_str(input.as_ref()).map(Match::from)
                    }
                    Rule::rule_match => RuleMatch::parse(pairs.into_inner()).map(Match::from),
                    _ => Err(Error::parser("unknown match format")),
                },
                _ => Err(Error::parser("match empty inner pairs")),
            },
            _ => Err(Error::parser("invalid match")),
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

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("rule={0} not found")]
    RuleNotFound(String),
    #[error("field={0} not found")]
    FieldNotFound(String),
    #[error("incompatible types field={path} expect={expect} got={got}")]
    IncompatibleTypes {
        path: String,
        expect: &'static str,
        got: &'static str,
    },
    #[error("match parser {0}")]
    Parser(String),
    #[error("{0}")]
    Path(#[from] PathError),
    #[error("{0}")]
    Pest(#[from] Box<pest::error::Error<Rule>>),
    #[error("{0}")]
    ParseNum(#[from] NumberError),
    #[error("{0}")]
    Regex(#[from] regex::Error),
}

impl Error {
    #[inline(always)]
    fn parser<S: AsRef<str>>(s: S) -> Self {
        Self::Parser(s.as_ref().into())
    }

    #[inline(always)]
    fn rule_not_found<S: AsRef<str>>(s: S) -> Self {
        Self::RuleNotFound(s.as_ref().into())
    }
}

impl MatchValue {
    fn value_regex(s: &str) -> Result<Self, Error> {
        Regex::new(s).map(Self::Regex).map_err(|e| e.into())
    }

    fn value_number<S: AsRef<str>>(s: S) -> Result<Self, Error> {
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
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MatchParser::parse_input(s)
    }
}

impl Match {
    #[inline]
    pub(crate) fn match_event<E: Event>(
        &self,
        event: &E,
        rule_state: &HashMap<Cow<'_, str>, bool>,
    ) -> Result<bool, Error> {
        match self {
            Self::Direct(m) => m.match_event(event),
            Self::Indirect(m) => m.match_event(event),
            Self::Rule(m) => m.match_event(rule_state),
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
    type Err = Error;

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
    pub(crate) fn match_event<E: Event>(&self, event: &E) -> Result<bool, Error> {
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
#[derive(Debug, Clone)]
enum Op {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    Rex,
    Flag,
}

/// DirectMatch represensts the needed information to perform a matching
/// operation on a log field
#[derive(Debug, Clone)]
pub(crate) struct DirectMatch {
    field_path: XPath,
    op: Op,
    value: MatchValue,
}

impl FromStr for DirectMatch {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut pairs = MatchParser::parse(Rule::direct_match, s).map_err(Box::new)?;

        let mut inner_pairs = pairs.next().unwrap().into_inner();

        // the code must not panic here as everything got validated by the parser
        let field_path = XPath::from_str(inner_pairs.next().unwrap().as_str()).unwrap();

        let rule_op = inner_pairs.next().unwrap().as_rule();

        let str_value = inner_pairs.next().unwrap().as_str();
        let is_none = str_value == "none";
        let is_some = str_value == "some";
        let is_bool_true = str_value.to_lowercase() == "true";
        let is_bool_false = str_value.to_lowercase() == "false";

        // easier to trim quotes here rather than walking parsed items
        let sanit_value = str_value.trim_matches('\'').trim_matches('"');

        let (op, value) = match rule_op {
            Rule::eq => (Op::Eq, {
                if is_none {
                    MatchValue::None
                } else if is_some {
                    MatchValue::Some
                } else if is_bool_true {
                    MatchValue::Bool(true)
                } else if is_bool_false {
                    MatchValue::Bool(false)
                } else if let Ok(i) = Number::from_str(sanit_value) {
                    // handle the case where string can also be an
                    // integer. Number::from_str manages hex prefix
                    MatchValue::StringOrNumber(sanit_value.into(), i)
                } else {
                    MatchValue::String(sanit_value.into())
                }
            }),
            Rule::lt => (Op::Lt, MatchValue::value_number(sanit_value)?),
            Rule::lte => (Op::Lte, MatchValue::value_number(sanit_value)?),
            Rule::gt => (Op::Gt, MatchValue::value_number(sanit_value)?),
            Rule::gte => (Op::Gte, MatchValue::value_number(sanit_value)?),
            Rule::rex => (Op::Rex, MatchValue::value_regex(sanit_value)?),
            Rule::flag => (Op::Flag, MatchValue::value_number(sanit_value)?),
            _ => unreachable!(),
        };

        let m = DirectMatch {
            field_path,
            op,
            value,
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
    pub(crate) fn match_event<E: Event>(&self, event: &E) -> Result<bool, Error> {
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
                Some(tgt.clone().try_into_number().map_err(|_| ())?)
            } else {
                None
            }
        };

        let fv = compat.as_ref().unwrap_or(tgt);

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
                    Ok((*v & *o) == *v)
                } else {
                    Err(())
                }
            }
            Op::Rex => {
                if let (MatchValue::Regex(v), FieldValue::String(o)) = (&self.value, &fv) {
                    Ok(v.is_match(o))
                } else {
                    Err(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RuleMatch(String);

impl RuleMatch {
    #[inline]
    fn parse(mut pairs: Pairs<'_, Rule>) -> Result<Self, Error> {
        match pairs.next() {
            Some(pairs) => match pairs.as_rule() {
                Rule::rule_name => Ok(RuleMatch(pairs.as_str().into())),
                _ => Err(Error::parser("invalid rule name")),
            },
            _ => Err(Error::parser("invalid rule match")),
        }
    }

    #[inline]
    pub(crate) fn match_event(&self, states: &HashMap<Cow<'_, str>, bool>) -> Result<bool, Error> {
        states
            .get(&Cow::from(&self.0))
            .copied()
            .ok_or(Error::rule_not_found(&self.0))
    }

    #[inline(always)]
    pub(crate) fn rule_name(&self) -> &str {
        &self.0
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

        assert!(DirectMatch::from_str(r#".data.exe.size > '42'"#)
            .unwrap()
            .match_value(&43.into())
            .unwrap());

        println!(
            "{:#?}",
            DirectMatch::from_str(r#".data.exe.size &= '0x100040'"#)
                .unwrap()
                .match_value(&0x40.into())
        );
        println!(
            "{:?}",
            DirectMatch::from_str(r#".data.exe.size ~= 'toast'"#)
                .unwrap()
                .match_value(&"toast".into())
        );

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
            RuleMatch("test".into())
        );

        assert_eq!(
            as_rule_match(MatchParser::parse_input("rule(blip.blop)").unwrap()),
            RuleMatch("blip.blop".into())
        )
    }
}
