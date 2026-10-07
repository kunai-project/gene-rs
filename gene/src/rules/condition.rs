use super::matcher::{self, Match};
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Op {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Expr {
    Variable(String),
    AllOfThem,
    AllOfVars(String),
    AnyOfThem,
    AnyOfVars(String),
    NoneOfThem,
    NoneOfVars(String),
    NOfThem(usize),
    NOfVars(usize, String),
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

impl FromStr for Expr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self::None);
        }

        let mut pairs = ConditionParser::parse(Rule::condition, s).map_err(Box::new)?;
        match pairs.next() {
            Some(pairs) => Ok(parse_expr(pairs.into_inner())),
            None => Ok(Self::None),
        }
    }
}

/// [`Expr`] with operands resolved to their index in the rule's operand
/// list, so evaluation does not look operands up by name.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) enum BoundExpr {
    Operand(usize),
    AllOf(Vec<usize>),
    AnyOf(Vec<usize>),
    NoneOf(Vec<usize>),
    NOf(usize, Vec<usize>),
    BinOp {
        lhs: Box<BoundExpr>,
        op: Op,
        rhs: Box<BoundExpr>,
    },
    Negate(Box<BoundExpr>),
    #[default]
    None,
}

impl BoundExpr {
    #[inline]
    fn compute_for_event<E>(
        &self,
        event: &E,
        operands: &[(String, Match)],
        mut ctx: Option<&mut ScanContext<'_, E>>,
    ) -> Result<bool, matcher::Error>
    where
        E: for<'e> Event<'e>,
    {
        let operand = |i: usize| {
            &operands
                .get(i)
                .expect("operand indexes come from Expr::bind over this operand list")
                .1
        };

        match self {
            BoundExpr::Operand(i) => operand(*i).match_event(event, ctx),
            BoundExpr::AllOf(idx) => {
                for &i in idx {
                    if !operand(i).match_event(event, ctx.as_deref_mut())? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BoundExpr::AnyOf(idx) => {
                for &i in idx {
                    if operand(i).match_event(event, ctx.as_deref_mut())? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            BoundExpr::NoneOf(idx) => {
                for &i in idx {
                    if operand(i).match_event(event, ctx.as_deref_mut())? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BoundExpr::NOf(n, idx) => {
                let mut c = 0;
                for &i in idx {
                    if operand(i).match_event(event, ctx.as_deref_mut())? {
                        c += 1;
                        if c >= *n {
                            return Ok(true);
                        }
                    }
                }
                Ok(c >= *n)
            }
            BoundExpr::BinOp { lhs, op, rhs } => match op {
                Op::And => Ok(lhs.compute_for_event(event, operands, ctx.as_deref_mut())?
                    && rhs.compute_for_event(event, operands, ctx)?),
                Op::Or => Ok(lhs.compute_for_event(event, operands, ctx.as_deref_mut())?
                    || rhs.compute_for_event(event, operands, ctx)?),
            },
            BoundExpr::Negate(expr) => Ok(!expr.compute_for_event(event, operands, ctx)?),
            BoundExpr::None => Ok(true),
        }
    }
}

impl Expr {
    /// Resolves operand names against `names`, given in the order the
    /// operands are stored in [`CompiledRule`](crate::rules::CompiledRule).
    /// Group operators keep that order, so evaluation order is unchanged.
    /// An undefined operand fails here, so it fails at compile time.
    fn bind(&self, names: &[&str]) -> Result<BoundExpr, ParseError> {
        let all = || (0..names.len()).collect::<Vec<_>>();
        let prefixed = |start: &str| {
            names
                .iter()
                .enumerate()
                .filter(|(_, n)| n.starts_with(start))
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        };

        Ok(match self {
            Expr::Variable(var) => match names.iter().position(|n| n == var) {
                Some(i) => BoundExpr::Operand(i),
                None => return Err(ParseError::UnknownOperand(var.clone())),
            },
            Expr::AllOfThem => BoundExpr::AllOf(all()),
            Expr::AllOfVars(start) => BoundExpr::AllOf(prefixed(start)),
            Expr::AnyOfThem => BoundExpr::AnyOf(all()),
            Expr::AnyOfVars(start) => BoundExpr::AnyOf(prefixed(start)),
            Expr::NoneOfThem => BoundExpr::NoneOf(all()),
            Expr::NoneOfVars(start) => BoundExpr::NoneOf(prefixed(start)),
            Expr::NOfThem(n) => BoundExpr::NOf(*n, all()),
            Expr::NOfVars(n, start) => BoundExpr::NOf(*n, prefixed(start)),
            Expr::BinOp { lhs, op, rhs } => BoundExpr::BinOp {
                lhs: Box::new(lhs.bind(names)?),
                op: *op,
                rhs: Box::new(rhs.bind(names)?),
            },
            Expr::Negate(expr) => BoundExpr::Negate(Box::new(expr.bind(names)?)),
            Expr::None => BoundExpr::None,
        })
    }

    #[allow(dead_code)]
    // this function is used in test
    fn compute(&self, operands: &HashMap<&str, bool>) -> Result<bool, matcher::Error> {
        match self {
            Expr::AllOfThem => Ok(operands.iter().all(|(_, &b)| b)),
            Expr::AllOfVars(start) => Ok(operands
                .iter()
                .filter(|(v, _)| v.starts_with(start))
                .all(|(_, &b)| b)),
            Expr::AnyOfThem => Ok(operands.iter().any(|(_, &b)| b)),
            Expr::AnyOfVars(start) => Ok(operands
                .iter()
                .filter(|(v, _)| v.starts_with(start))
                .any(|(_, &b)| b)),
            Expr::NoneOfThem => Ok(!operands.iter().any(|(_, &b)| b)),
            Expr::NoneOfVars(start) => Ok(!operands
                .iter()
                .filter(|(v, _)| v.starts_with(start))
                .any(|(_, &b)| b)),
            Expr::NOfThem(x) => {
                if operands.len() < *x {
                    return Ok(false);
                }
                for (c, _) in operands.iter().filter(|(_, &b)| b).enumerate() {
                    // +1 because we start iterating at 0 ><
                    if c + 1 >= *x {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Expr::NOfVars(x, start) => {
                if operands.len() < *x {
                    return Ok(false);
                }
                for (c, _) in operands
                    .iter()
                    .filter(|(v, &b)| b && v.starts_with(start))
                    .enumerate()
                {
                    // +1 because we start iterating at 0 ><
                    if c + 1 >= *x {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Expr::Variable(var) => Ok(*(operands.get(var.as_str()).unwrap())),
            Expr::BinOp { lhs, op, rhs } => match op {
                Op::And => Ok(lhs.compute(operands)? && rhs.compute(operands)?),
                Op::Or => Ok(lhs.compute(operands)? || rhs.compute(operands)?),
            },
            Expr::Negate(expr) => Ok(!expr.compute(operands)?),
            Expr::None => Ok(true),
        }
    }
}

fn parse_expr(pairs: Pairs<Rule>) -> Expr {
    PRATT_PARSER
        .map_primary(|primary| match primary.as_rule() {
            Rule::var => Expr::Variable(primary.as_str().into()),
            Rule::all_of_them => Expr::AllOfThem,
            Rule::all_of_vars => {
                Expr::AllOfVars(primary.as_str().rsplit_once(' ').unwrap().1.into())
            }
            Rule::none_of_them => Expr::NoneOfThem,
            Rule::none_of_vars => {
                Expr::NoneOfVars(primary.as_str().rsplit_once(' ').unwrap().1.into())
            }
            Rule::any_of_them => Expr::AnyOfThem,
            Rule::any_of_vars => {
                Expr::AnyOfVars(primary.as_str().rsplit_once(' ').unwrap().1.into())
            }
            Rule::n_of_them => {
                // this should not panic in anyways as it is validated by pest
                let n = // this should not panic in anyways as it is validated by pest
                primary
                    .as_str()
                    .split_once(' ')
                    .unwrap()
                    .0
                    .parse::<usize>()
                    .unwrap();
                if n == 0 {
                    // equivalent to none of them
                    return Expr::NoneOfThem;
                }
                Expr::NOfThem(n)
            }
            Rule::n_of_vars => {
                let n = primary
                    .as_str()
                    .split_once(' ')
                    .unwrap()
                    .0
                    .parse::<usize>()
                    .unwrap();
                let vars = primary.as_str().rsplit_once(' ').unwrap().1.into();
                if n == 0 {
                    return Expr::NoneOfVars(vars);
                }
                Expr::NOfVars(n, vars)
            }
            Rule::expr | Rule::ident | Rule::group => parse_expr(primary.into_inner()),
            rule => unreachable!("Expr::parse expected atom, found {:?}", rule),
        })
        .map_infix(|lhs, op, rhs| {
            let op = match op.as_rule() {
                Rule::and => Op::And,
                Rule::or => Op::Or,
                rule => unreachable!("Expr::parse expected infix operation, found {:?}", rule),
            };
            Expr::BinOp {
                lhs: Box::new(lhs),
                op,
                rhs: Box::new(rhs),
            }
        })
        .map_prefix(|op, rhs| match op.as_rule() {
            Rule::negate => Expr::Negate(Box::new(rhs)),
            _ => unreachable!(),
        })
        .parse(pairs)
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Condition {
    pub(crate) expr: Expr,
    bound: BoundExpr,
}

impl FromStr for Condition {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Expr::from_str(s)?.into())
    }
}

impl From<Expr> for Condition {
    fn from(value: Expr) -> Self {
        Self {
            expr: value,
            bound: BoundExpr::None,
        }
    }
}

impl Condition {
    pub(crate) fn compute_for_event<E>(
        &self,
        event: &E,
        operands: &[(String, Match)],
        ctx: Option<&mut ScanContext<'_, E>>,
    ) -> Result<bool, matcher::Error>
    where
        E: for<'e> Event<'e>,
    {
        self.bound.compute_for_event(event, operands, ctx)
    }

    /// Resolves the condition against the rule's final operand list. An
    /// operand the condition uses but the rule does not define is an error.
    pub(crate) fn bind(&mut self, operands: &[(String, Match)]) -> Result<(), ParseError> {
        let names: Vec<&str> = operands.iter().map(|(n, _)| n.as_str()).collect();
        self.bound = self.expr.bind(&names)?;
        Ok(())
    }
}

mod condition_test;

#[cfg(test)]
mod tests {

    use pest::Parser;

    use super::*;

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
            println!("{:?}", Expr::from_str(ident).unwrap());
        });

        // special cases
        assert_eq!("0 of them".parse::<Expr>().unwrap(), Expr::NoneOfThem);

        assert_eq!(
            "0 of $app".parse::<Expr>().unwrap(),
            Expr::NoneOfVars("$app".into())
        );
    }

    #[test]
    fn test_all_of_them() {
        let expr = Expr::from_str("all of them").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$a", true);
            m.insert("$b", true);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.insert("$c", false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }

    #[test]
    fn test_all_of_vars() {
        let expr = Expr::from_str("all of $app").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$app1", true);
            m.insert("$app2", true);
            m.insert("$b", false);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.insert("$app3", false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }

    #[test]
    fn test_any_of_them() {
        let expr = Expr::from_str("any of them").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$a", true);
            m.insert("$b", false);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.entry("$a").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }

    #[test]
    fn test_any_of_vars() {
        let expr = Expr::from_str("any of $app").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$app1", true);
            m.insert("$app2", false);
            m.insert("$b", true);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.entry("$app1").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }

    #[test]
    fn test_none_of_them() {
        let expr = Expr::from_str("none of them").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$a", true);
            m.insert("$b", false);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(false));
        operands.entry("$a").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(true));
    }

    #[test]
    fn test_none_of_vars() {
        let expr = Expr::from_str("none of $app").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$app1", true);
            m.insert("$app2", true);
            m.insert("$b", false);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(false));
        operands.entry("$app1").and_modify(|b| *b = false);
        operands.entry("$app2").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(true));
    }

    #[test]
    fn test_x_of_them() {
        let expr = Expr::from_str("1 of them").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$a", true);
            m.insert("$b", false);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.entry("$a").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }

    #[test]
    fn test_x_of_vars() {
        let expr = Expr::from_str("1 of $app").unwrap();
        let mut operands = {
            let mut m = HashMap::new();
            m.insert("$app1", true);
            m.insert("$app2", false);
            m.insert("$b", true);
            m
        };

        assert_eq!(expr.compute(&operands), Ok(true));
        operands.entry("$app1").and_modify(|b| *b = false);
        assert_eq!(expr.compute(&operands), Ok(false));
    }
}
