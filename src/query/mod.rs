#![allow(dead_code)]

use anyhow::{Result, bail};
use regex::Regex;

#[derive(Debug, Clone)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Field, Op, Value),
}

#[derive(Debug, Clone, Copy)]
pub enum Field {
    ReqMethod,
    ReqUri,
    ReqHost,
    ResStatus,
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Eq,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Gte,
    Lte,
}

#[derive(Debug, Clone)]
pub enum Value {
    Str(String),
    Int(i64),
    Regex(Regex),
}

#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub req_method: Option<String>,
    pub req_uri: Option<String>,
    pub req_host: Option<String>,
    pub res_status: Option<u16>,
}

impl Expr {
    pub fn eval(&self, ctx: &EvalContext) -> bool {
        match self {
            Expr::And(a, b) => a.eval(ctx) && b.eval(ctx),
            Expr::Or(a, b) => a.eval(ctx) || b.eval(ctx),
            Expr::Cmp(field, op, value) => match (field, op, value) {
                (Field::ReqMethod, Op::Eq, Value::Str(s)) => {
                    ctx.req_method.as_ref().map(|m| m == s).unwrap_or(false)
                }
                (Field::ReqUri, Op::Eq, Value::Str(s)) => {
                    ctx.req_uri.as_ref().map(|u| u == s).unwrap_or(false)
                }
                (Field::ReqUri, Op::Contains, Value::Str(s)) => {
                    ctx.req_uri.as_ref().map(|u| u.contains(s)).unwrap_or(false)
                }
                (Field::ReqUri, Op::StartsWith, Value::Str(s)) => ctx
                    .req_uri
                    .as_ref()
                    .map(|u| u.starts_with(s))
                    .unwrap_or(false),
                (Field::ReqUri, Op::EndsWith, Value::Str(s)) => ctx
                    .req_uri
                    .as_ref()
                    .map(|u| u.ends_with(s))
                    .unwrap_or(false),
                (Field::ReqUri, Op::Matches, Value::Regex(re)) => ctx
                    .req_uri
                    .as_ref()
                    .map(|u| re.is_match(u))
                    .unwrap_or(false),
                (Field::ReqHost, Op::Eq, Value::Str(s)) => {
                    ctx.req_host.as_ref().map(|h| h == s).unwrap_or(false)
                }
                (Field::ReqHost, Op::Contains, Value::Str(s)) => ctx
                    .req_host
                    .as_ref()
                    .map(|h| h.contains(s))
                    .unwrap_or(false),
                (Field::ReqHost, Op::StartsWith, Value::Str(s)) => ctx
                    .req_host
                    .as_ref()
                    .map(|h| h.starts_with(s))
                    .unwrap_or(false),
                (Field::ReqHost, Op::EndsWith, Value::Str(s)) => ctx
                    .req_host
                    .as_ref()
                    .map(|h| h.ends_with(s))
                    .unwrap_or(false),
                (Field::ReqHost, Op::Matches, Value::Regex(re)) => ctx
                    .req_host
                    .as_ref()
                    .map(|h| re.is_match(h))
                    .unwrap_or(false),
                (Field::ReqMethod, Op::Contains, Value::Str(s)) => ctx
                    .req_method
                    .as_ref()
                    .map(|m| m.contains(s))
                    .unwrap_or(false),
                (Field::ReqMethod, Op::StartsWith, Value::Str(s)) => ctx
                    .req_method
                    .as_ref()
                    .map(|m| m.starts_with(s))
                    .unwrap_or(false),
                (Field::ReqMethod, Op::EndsWith, Value::Str(s)) => ctx
                    .req_method
                    .as_ref()
                    .map(|m| m.ends_with(s))
                    .unwrap_or(false),
                (Field::ReqMethod, Op::Matches, Value::Regex(re)) => ctx
                    .req_method
                    .as_ref()
                    .map(|m| re.is_match(m))
                    .unwrap_or(false),
                (Field::ResStatus, Op::Eq, Value::Int(i)) => {
                    ctx.res_status.map(|x| x as i64 == *i).unwrap_or(false)
                }
                (Field::ResStatus, Op::Gte, Value::Int(i)) => {
                    ctx.res_status.map(|x| x as i64 >= *i).unwrap_or(false)
                }
                (Field::ResStatus, Op::Lte, Value::Int(i)) => {
                    ctx.res_status.map(|x| x as i64 <= *i).unwrap_or(false)
                }
                _ => false,
            },
        }
    }
}

pub fn parse(input: &str) -> Result<Expr> {
    let input = input.trim();
    if input.is_empty() {
        bail!("empty expression");
    }

    if let Some((lhs, rhs)) = split_top_level(input, "||") {
        return Ok(Expr::Or(Box::new(parse(lhs)?), Box::new(parse(rhs)?)));
    }
    if let Some((lhs, rhs)) = split_top_level(input, "&&") {
        return Ok(Expr::And(Box::new(parse(lhs)?), Box::new(parse(rhs)?)));
    }

    parse_cmp(input)
}

fn parse_cmp(input: &str) -> Result<Expr> {
    let (op, parts) = if let Some(parts) = input.split_once(" matches ") {
        (Op::Matches, parts)
    } else if let Some(parts) = input.split_once(" starts_with ") {
        (Op::StartsWith, parts)
    } else if let Some(parts) = input.split_once(" ends_with ") {
        (Op::EndsWith, parts)
    } else if let Some(parts) = input.split_once("==") {
        (Op::Eq, parts)
    } else if let Some(parts) = input.split_once("~=") {
        (Op::Contains, parts)
    } else if let Some(parts) = input.split_once(">=") {
        (Op::Gte, parts)
    } else if let Some(parts) = input.split_once("<=") {
        (Op::Lte, parts)
    } else {
        bail!("unsupported operator in expression: {input}");
    };

    let field = match parts.0.trim() {
        "req.method" => Field::ReqMethod,
        "req.uri" => Field::ReqUri,
        "req.host" => Field::ReqHost,
        "res.status" => Field::ResStatus,
        x => bail!("unsupported field: {x}"),
    };

    let raw = parts.1.trim();
    let value = match field {
        Field::ReqMethod | Field::ReqUri | Field::ReqHost if matches!(op, Op::Matches) => {
            Value::Regex(Regex::new(&parse_string_value(raw)?)?)
        }
        Field::ReqMethod | Field::ReqUri | Field::ReqHost => Value::Str(parse_string_value(raw)?),
        Field::ResStatus => Value::Int(raw.parse()?),
    };

    Ok(Expr::Cmp(field, op, value))
}

fn parse_string_value(raw: &str) -> Result<String> {
    Ok(raw.trim_matches('"').to_string())
}

fn split_top_level<'a>(input: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0_i32;
    let bytes = input.as_bytes();
    let sep_bytes = sep.as_bytes();
    let mut i = 0usize;
    while i + sep_bytes.len() <= bytes.len() {
        let c = bytes[i] as char;
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && &bytes[i..i + sep_bytes.len()] == sep_bytes {
            return Some((input[..i].trim(), input[i + sep_bytes.len()..].trim()));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expr_eval() {
        let expr = parse(r#"req.method == "POST" && res.status >= 400"#).expect("parse");
        let ctx = EvalContext {
            req_method: Some("POST".into()),
            res_status: Some(500),
            ..EvalContext::default()
        };
        assert!(expr.eval(&ctx));
    }

    #[test]
    fn test_host_contains() {
        let expr = parse(r#"req.host ~= "example.com""#).expect("parse");
        let ctx = EvalContext {
            req_host: Some("api.example.com".into()),
            ..EvalContext::default()
        };
        assert!(expr.eval(&ctx));
    }

    #[test]
    fn test_starts_with_and_ends_with() {
        let expr = parse(r#"req.uri starts_with "/api/" && req.host ends_with ".example.com""#)
            .expect("parse");
        let ctx = EvalContext {
            req_uri: Some("/api/v1/items".into()),
            req_host: Some("svc.example.com".into()),
            ..EvalContext::default()
        };
        assert!(expr.eval(&ctx));
    }

    #[test]
    fn test_regex_lite_matches() {
        let expr = parse(r#"req.uri matches "^/api/v[0-9]+/items$""#).expect("parse");
        let ctx = EvalContext {
            req_uri: Some("/api/v2/items".into()),
            ..EvalContext::default()
        };
        assert!(expr.eval(&ctx));
    }

    #[test]
    fn invalid_regex_fails_at_parse_time() {
        let err = parse(r#"req.uri matches "[""#).expect_err("invalid regex should fail");
        assert!(err.to_string().contains("regex parse error"));
    }

    #[test]
    fn method_contains_is_supported() {
        let expr = parse(r#"req.method ~= "POS""#).expect("parse");
        let ctx = EvalContext {
            req_method: Some("POST".into()),
            ..EvalContext::default()
        };
        assert!(expr.eval(&ctx));
    }
}
