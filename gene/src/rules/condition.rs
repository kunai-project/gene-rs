use super::matcher::{self, Match};
use crate::Event;
use pest::{iterators::Pairs, pratt_parser::PrattParser, Parser};
use std::{collections::HashMap, str::FromStr};
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

#[derive(Debug, Clone)]
pub(crate) enum Op {
    And,
    Or,
}

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Variable(String),
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

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown operand {0}")]
    UnknowOperand(String),
    #[error("{0}")]
    Parser(#[from] Box<pest::error::Error<Rule>>),
    #[error("{0}")]
    Matcher(#[from] matcher::Error),
}

impl FromStr for Expr {
    type Err = Error;

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

impl Expr {
    #[inline]
    fn compute_for_event<E: Event>(
        &self,
        operands: &HashMap<String, Match>,
        event: &E,
    ) -> Result<bool, Error> {
        match self {
            Expr::Variable(var) => {
                if let Some(m) = operands.get(var) {
                    return m.match_event(event).map_err(|e| e.into());
                }
                Err(Error::UnknowOperand(var.into()))
            }
            Expr::BinOp { lhs, op, rhs } => match op {
                Op::And => Ok(lhs.compute_for_event(operands, event)?
                    && rhs.compute_for_event(operands, event)?),
                Op::Or => Ok(lhs.compute_for_event(operands, event)?
                    || rhs.compute_for_event(operands, event)?),
            },
            Expr::Negate(expr) => Ok(!expr.compute_for_event(operands, event)?),
            Expr::None => Ok(true),
        }
    }

    #[allow(dead_code)]
    // this function is used in test
    fn compute(&self, operands: &HashMap<&str, bool>) -> bool {
        match self {
            Expr::Variable(var) => *(operands.get(var.as_str()).unwrap()),
            Expr::BinOp { lhs, op, rhs } => match op {
                Op::And => lhs.compute(operands) && rhs.compute(operands),
                Op::Or => lhs.compute(operands) || rhs.compute(operands),
            },
            Expr::Negate(expr) => !expr.compute(operands),
            Expr::None => true,
        }
    }
}

fn parse_expr(pairs: Pairs<Rule>) -> Expr {
    PRATT_PARSER
        .map_primary(|primary| match primary.as_rule() {
            Rule::ident => Expr::Variable(primary.as_str().into()),
            Rule::expr => parse_expr(primary.into_inner()),
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
}

impl FromStr for Condition {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Expr::from_str(s)?.into())
    }
}

impl From<Expr> for Condition {
    fn from(value: Expr) -> Self {
        Self { expr: value }
    }
}

impl Condition {
    pub(crate) fn compute_for_event<E: Event>(
        &self,
        operands: &HashMap<String, Match>,
        event: &E,
    ) -> Result<bool, Error> {
        self.expr.compute_for_event(operands, event)
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
            if ConditionParser::parse(Rule::_ident_test, ident).is_ok() {
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
        ];

        valid.iter().for_each(|ident| {
            Expr::from_str(ident).unwrap();
        });
    }
}
