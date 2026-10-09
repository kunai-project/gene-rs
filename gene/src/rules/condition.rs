use super::matcher::{self, Match};
use super::CompileError;
use crate::engine::ScanContext;
use crate::Event;
use pest::{iterators::Pairs, pratt_parser::PrattParser, Parser};
use std::{collections::HashMap, hash::Hash, str::FromStr};
use thiserror::Error;

#[derive(pest_derive::Parser)]
#[grammar = "rules/grammars/condition.pest"]
pub struct ConditionParser;

lazy_static::lazy_static! {
    static ref PRATT_PARSER: PrattParser<Rule> = {
        use pest::pratt_parser::{Assoc::*, Op};
        use Rule::*;

        // Precedence is defined lowest to highest
        PrattParser::new()
        // or has lower prio
        .op(Op::infix(or, Left))
        // and has higher prio
        .op(Op::infix(and, Left))
        .op(Op::prefix(negate))
    };
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    And,
    Or,
}

/// Condition expression whose operands are indexes into the rule's matches.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Expr {
    Variable(usize),
    AllOf(Vec<usize>),
    AnyOf(Vec<usize>),
    NoneOf(Vec<usize>),
    NOf(usize, Vec<usize>),
    BinOp {
        lhs: Box<Expr>,
        op: Op,
        rhs: Box<Expr>,
    },
    Negate(Box<Expr>),
    None,
}

impl Default for Expr {
    fn default() -> Self {
        Self::None
    }
}

/// Error raised while parsing a condition.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParseError {
    /// The condition references an operand not defined in `matches`.
    #[error("unknown operand {0}")]
    UnknownOperand(String),
    /// Syntax error in the condition.
    #[error("{0}")]
    Parser(#[from] Box<pest::error::Error<Rule>>),
}

/// Named match operands of a rule, in evaluation order.
#[derive(Debug, Default, Clone)]
pub(crate) struct Operands {
    names: Vec<String>,
    matches: Vec<Match>,
}

impl Operands {
    /// Parses `$name: expression` pairs.
    pub(crate) fn compile(raw: HashMap<String, String>) -> Result<Self, CompileError> {
        let mut pairs = Vec::with_capacity(raw.len());
        for (name, s) in raw {
            if !name.starts_with('$') {
                return Err(CompileError::InvalidOperand(name));
            }
            let m = Match::from_str(&s)?;
            pairs.push((name, m));
        }
        // cheapest first so that `of` conditions short-circuit early,
        // name as tie-breaker keeps evaluation order deterministic
        pairs.sort_unstable_by(|a, b| (a.1.cost(), &a.0).cmp(&(b.1.cost(), &b.0)));
        let (names, matches) = pairs.into_iter().unzip();
        Ok(Self { names, matches })
    }

    #[inline]
    pub(crate) fn matches(&self) -> impl Iterator<Item = &Match> {
        self.matches.iter()
    }

    #[inline]
    pub(crate) fn matches_mut(&mut self) -> impl Iterator<Item = &mut Match> {
        self.matches.iter_mut()
    }

    /// Counts operands at `idx` evaluating to `expected`, stopping once `limit` is reached.
    #[inline]
    fn count<E>(
        &self,
        idx: &[usize],
        event: &E,
        mut ctx: Option<&mut ScanContext<'_, E>>,
        expected: bool,
        limit: usize,
    ) -> Result<usize, matcher::Error>
    where
        E: for<'e> Event<'e>,
    {
        let mut c = 0;
        for &i in idx {
            if self.matches[i].match_event(event, ctx.as_deref_mut())? == expected {
                c += 1;
                if c >= limit {
                    break;
                }
            }
        }
        Ok(c)
    }
}

impl Expr {
    /// Parses `s`, resolving operand names to their index in `operands`.
    fn parse<S: AsRef<str>>(s: &str, operands: &[S]) -> Result<Self, ParseError> {
        if s.is_empty() {
            return Ok(Self::None);
        }

        let mut pairs = ConditionParser::parse(Rule::condition, s).map_err(Box::new)?;
        match pairs.next() {
            Some(pairs) => parse_expr(pairs.into_inner(), operands),
            None => Ok(Self::None),
        }
    }

    #[inline]
    fn compute_for_event<E>(
        &self,
        event: &E,
        operands: &Operands,
        mut ctx: Option<&mut ScanContext<'_, E>>,
    ) -> Result<bool, matcher::Error>
    where
        E: for<'e> Event<'e>,
    {
        match self {
            Expr::AllOf(idx) => Ok(operands.count(idx, event, ctx, false, 1)? == 0),
            Expr::AnyOf(idx) => Ok(operands.count(idx, event, ctx, true, 1)? == 1),
            Expr::NoneOf(idx) => Ok(operands.count(idx, event, ctx, true, 1)? == 0),
            Expr::NOf(n, idx) => Ok(operands.count(idx, event, ctx, true, *n)? >= *n),
            Expr::Variable(i) => operands.matches[*i].match_event(event, ctx),
            Expr::BinOp { lhs, op, rhs } => match op {
                Op::And => Ok(lhs.compute_for_event(event, operands, ctx.as_deref_mut())?
                    && rhs.compute_for_event(event, operands, ctx)?),
                Op::Or => Ok(lhs.compute_for_event(event, operands, ctx.as_deref_mut())?
                    || rhs.compute_for_event(event, operands, ctx)?),
            },
            Expr::Negate(expr) => Ok(!expr.compute_for_event(event, operands, ctx)?),
            Expr::None => Ok(true),
        }
    }

    #[cfg(test)]
    fn compute(&self, operands: &[bool]) -> bool {
        let count = |idx: &[usize]| idx.iter().filter(|&&i| operands[i]).count();
        match self {
            Expr::AllOf(idx) => count(idx) == idx.len(),
            Expr::AnyOf(idx) => count(idx) > 0,
            Expr::NoneOf(idx) => count(idx) == 0,
            Expr::NOf(n, idx) => count(idx) >= *n,
            Expr::Variable(i) => operands[*i],
            Expr::BinOp { lhs, op, rhs } => match op {
                Op::And => lhs.compute(operands) && rhs.compute(operands),
                Op::Or => lhs.compute(operands) || rhs.compute(operands),
            },
            Expr::Negate(expr) => !expr.compute(operands),
            Expr::None => true,
        }
    }
}

fn parse_expr<S: AsRef<str>>(pairs: Pairs<Rule>, operands: &[S]) -> Result<Expr, ParseError> {
    // pest guarantees "<n|kw> of <them|prefix>" for *_of_* rules
    let vars = |s: &str| -> Vec<usize> {
        let prefix = match s.rsplit_once(' ').unwrap().1 {
            "them" => "",
            p => p,
        };
        (0..operands.len())
            .filter(|&i| operands[i].as_ref().starts_with(prefix))
            .collect()
    };
    // pest guarantees a leading integer for n_of_* rules
    let count = |s: &str| s.split_once(' ').unwrap().0.parse::<usize>().unwrap();

    PRATT_PARSER
        .map_primary(|primary| match primary.as_rule() {
            Rule::var => operands
                .iter()
                .position(|o| o.as_ref() == primary.as_str())
                .map(Expr::Variable)
                .ok_or_else(|| ParseError::UnknownOperand(primary.as_str().into())),
            Rule::all_of_them | Rule::all_of_vars => Ok(Expr::AllOf(vars(primary.as_str()))),
            Rule::none_of_them | Rule::none_of_vars => Ok(Expr::NoneOf(vars(primary.as_str()))),
            Rule::any_of_them | Rule::any_of_vars => Ok(Expr::AnyOf(vars(primary.as_str()))),
            Rule::n_of_them | Rule::n_of_vars => {
                let idx = vars(primary.as_str());
                match count(primary.as_str()) {
                    0 => Ok(Expr::NoneOf(idx)),
                    n => Ok(Expr::NOf(n, idx)),
                }
            }
            Rule::expr | Rule::ident | Rule::group => parse_expr(primary.into_inner(), operands),
            rule => unreachable!("Expr::parse expected atom, found {:?}", rule),
        })
        .map_infix(|lhs, op, rhs| {
            let op = match op.as_rule() {
                Rule::and => Op::And,
                Rule::or => Op::Or,
                rule => unreachable!("Expr::parse expected infix operation, found {:?}", rule),
            };
            Ok(Expr::BinOp {
                lhs: Box::new(lhs?),
                op,
                rhs: Box::new(rhs?),
            })
        })
        .map_prefix(|op, rhs| match op.as_rule() {
            Rule::negate => Ok(Expr::Negate(Box::new(rhs?))),
            _ => unreachable!(),
        })
        .parse(pairs)
}

/// Condition owning the operands its expression indexes into, so the two
/// cannot get out of sync.
#[derive(Debug, Default, Clone)]
pub(crate) struct Condition {
    expr: Expr,
    operands: Operands,
}

impl Condition {
    /// Parses `s`, resolving operand names to their index in `operands`.
    pub(crate) fn parse(s: &str, operands: Operands) -> Result<Self, ParseError> {
        let expr = Expr::parse(s, &operands.names)?;
        Ok(Self { expr, operands })
    }

    #[inline]
    pub(crate) fn operands(&self) -> &Operands {
        &self.operands
    }

    #[inline]
    pub(crate) fn operands_mut(&mut self) -> &mut Operands {
        &mut self.operands
    }

    pub(crate) fn compute_for_event<E>(
        &self,
        event: &E,
        ctx: Option<&mut ScanContext<'_, E>>,
    ) -> Result<bool, matcher::Error>
    where
        E: for<'e> Event<'e>,
    {
        self.expr.compute_for_event(event, &self.operands, ctx)
    }
}

mod condition_test;

#[cfg(test)]
mod tests {

    use pest::Parser;

    use super::*;

    fn compute(cond: &str, operands: &[(&str, bool)]) -> bool {
        let names: Vec<&str> = operands.iter().map(|(n, _)| *n).collect();
        let values: Vec<bool> = operands.iter().map(|(_, b)| *b).collect();
        Expr::parse(cond, &names).unwrap().compute(&values)
    }

    #[test]
    fn test_operands_order() {
        let raw = [
            ("$a", "rule(dep)"),
            ("$b", ".x ~= 'x'"),
            ("$c", ".x == @.y"),
            ("$d", ".x == 'x'"),
            ("$f", ".x == true"),
            ("$e", ".x == false"),
        ]
        .into_iter()
        .map(|(n, m)| (n.to_string(), m.to_string()))
        .collect();

        let ops = Operands::compile(raw).unwrap();
        assert_eq!(ops.names, ["$e", "$f", "$d", "$c", "$b", "$a"]);
    }

    #[test]
    fn test_idents() {
        let good = ["$test", "$test_1", "$a", "$A42", "$A_42"];

        good.iter().for_each(|ident| {
            ConditionParser::parse(Rule::ident, ident).unwrap();
        });

        let bad = ["a", "$a b", "$a-t"];

        bad.iter().for_each(|ident| {
            if ConditionParser::parse(Rule::condition, ident).is_ok() {
                panic!("{ident} should produce an error")
            }
        });
    }

    #[test]
    fn test_condition() {
        let operands = ["$a", "$b", "$c", "$d", "$app_1"];
        let valid = [
            "",
            "$a",
            "$a and $b",
            "$a and ($b or ($c and $d))",
            "($a or $b) and $c",
            "any of them",
            "any of $app_",
            "all of them",
            "all of $app_",
            "none of them",
            "none of $app_",
            "42 of them",
            "42 of $app_",
        ];

        valid.iter().for_each(|ident| {
            println!("{:?}", Expr::parse(ident, &operands).unwrap());
        });

        // special cases
        assert_eq!(
            Expr::parse("0 of them", &operands).unwrap(),
            Expr::NoneOf(vec![0, 1, 2, 3, 4])
        );

        assert_eq!(
            Expr::parse("0 of $app", &operands).unwrap(),
            Expr::NoneOf(vec![4])
        );
    }

    #[test]
    fn test_unknown_operand() {
        assert_eq!(
            Expr::parse("$a and !$c", &["$a", "$b"]),
            Err(ParseError::UnknownOperand("$c".into()))
        );
    }

    #[test]
    fn test_all_of_them() {
        assert!(compute("all of them", &[("$a", true), ("$b", true)]));
        assert!(!compute(
            "all of them",
            &[("$a", true), ("$b", true), ("$c", false)]
        ));
    }

    #[test]
    fn test_all_of_vars() {
        let mut operands = vec![("$app1", true), ("$app2", true), ("$b", false)];
        assert!(compute("all of $app", &operands));
        operands.push(("$app3", false));
        assert!(!compute("all of $app", &operands));
    }

    #[test]
    fn test_any_of_them() {
        assert!(compute("any of them", &[("$a", true), ("$b", false)]));
        assert!(!compute("any of them", &[("$a", false), ("$b", false)]));
    }

    #[test]
    fn test_any_of_vars() {
        assert!(compute(
            "any of $app",
            &[("$app1", true), ("$app2", false), ("$b", true)]
        ));
        assert!(!compute(
            "any of $app",
            &[("$app1", false), ("$app2", false), ("$b", true)]
        ));
    }

    #[test]
    fn test_none_of_them() {
        assert!(!compute("none of them", &[("$a", true), ("$b", false)]));
        assert!(compute("none of them", &[("$a", false), ("$b", false)]));
    }

    #[test]
    fn test_none_of_vars() {
        assert!(!compute(
            "none of $app",
            &[("$app1", true), ("$app2", true), ("$b", false)]
        ));
        assert!(compute(
            "none of $app",
            &[("$app1", false), ("$app2", false), ("$b", true)]
        ));
    }

    #[test]
    fn test_x_of_them() {
        assert!(compute("1 of them", &[("$a", true), ("$b", false)]));
        assert!(!compute("1 of them", &[("$a", false), ("$b", false)]));
        assert!(!compute("3 of them", &[("$a", true), ("$b", true)]));
    }

    #[test]
    fn test_x_of_vars() {
        assert!(compute(
            "1 of $app",
            &[("$app1", true), ("$app2", false), ("$b", true)]
        ));
        assert!(!compute(
            "1 of $app",
            &[("$app1", false), ("$app2", false), ("$b", true)]
        ));
    }
}
