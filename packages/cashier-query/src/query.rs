use nom::IResult;
use nom::combinator::{all_consuming, opt, map, not, verify, value};
use nom::sequence::{preceded, terminated, pair, tuple};
use nom::character::complete::{multispace0, multispace1};
use nom::bytes::complete::{tag_no_case, tag, take};
use nom::branch::alt;
use nom::multi::{separated_nonempty_list, many0, many1};

// modified from https://github.com/elastic/kibana/blob/master/src/plugins/data/common/es_query/kuery/ast/kuery.peg

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum OrderOperator {
    Lte,
    Gte,
    Lt,
    Gt,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Query {
    Or {
        queries: Vec<Query>,
    },
    And {
        queries: Vec<Query>,
    },
    Not {
        query: Box<Query>,
    },
    Equal {
        field: Option<String>,
        value: Option<String>,
    },
    Order {
        field: Option<String>,
        operator: OrderOperator,
        value: String,
    },
}

pub fn parse_range_operator(input: &str) -> IResult<&str, OrderOperator> {
    alt((
        value(OrderOperator::Lte, tag("<=")),
        value(OrderOperator::Gte, tag(">=")),
        value(OrderOperator::Lt, tag("<")),
        value(OrderOperator::Gt, tag(">")),
    ))(input)
}

// Or = Space+ 'or'i Space+
pub fn parse_or(input: &str) -> IResult<&str, Option<&str>> {
    preceded(
        multispace1,
        opt(terminated(
            tag_no_case("or"),
            multispace1,
        ))
    )(input)
}

// And = Space+ 'and'i Space+
pub fn parse_and(input: &str) -> IResult<&str, &str> {
    preceded(
        multispace1,
        terminated(
            tag_no_case("and"),
            multispace1,
        )
    )(input)
}

// Not = 'not'i Space+
pub fn parse_not(input: &str) -> IResult<&str, &str> {
    terminated(
        tag_no_case("not"),
        multispace1,
    )(input)
}

// EscapedWhitespace = '\\t'
//                   | '\\r'
//                   | '\\n'
pub fn parse_escaped_whitespace(input: &str) -> IResult<&str, &str> {
    alt((
        value("\t", tag("\\t")),
        value("\r", tag("\\r")),
        value("\n", tag("\\n")),
    ))(input)
}

// UnquotedCharacter = [^\\():<>"@* \t\r\n]
pub fn parse_unquoted_character(input: &str) -> IResult<&str, &str> {
    preceded(
        not(alt((
            tag("\\"),
            tag("("),
            tag(")"),
            tag(":"),
            tag("<"),
            tag(">"),
            tag("\""),
            tag("@"),
            tag("*"),
            tag(" "),
            tag("\t"),
            tag("\r"),
            tag("\n"),
        ))),
        take(1usize)
    )(input)
}

// UnquotedLiteral = UnquotedCharacter
pub fn parse_unquoted_literal(input: &str) -> IResult<&str, String> {
    verify(
        map(many1(parse_unquoted_character), |chars| chars.join("")),
        |string: &str| {
            let string = string.to_ascii_lowercase();
            string != "and" && string != "or" && string != "not"
        },
    )(input)
}

// QuotedCharacter = EscapedWhitespace
//                 | '\\' [\\"]
//                 | [^"]
pub fn parse_quoted_character(input: &str) -> IResult<&str, &str> {
    alt((
        parse_escaped_whitespace,
        preceded(
            tag("\\"),
            alt((tag("\\"), tag("\""))),
        ),
        preceded(
            not(tag("\"")),
            take(1usize)
        ),
    ))(input)
}

// '"' QuotedCharacter* '"'
pub fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    map(preceded(
        tag("\""),
        terminated(
            many0(parse_quoted_character),
            tag("\""),
        ),
    ), |chars| chars.join(""))(input)
}

// Literal = QuotedString | UnquotedLiteral
pub fn parse_literal(input: &str) -> IResult<&str, String> {
    alt((
        parse_quoted_string,
        parse_unquoted_literal,
    ))(input)
}

// NullableLiteral = QuotedString | UnquotedLiteral
pub fn parse_nullable_literal(input: &str) -> IResult<&str, Option<String>> {
    alt((
        value(None, parse_quoted_string),
        map(parse_unquoted_literal, |v| if v.to_ascii_lowercase() == "null" {
            None } else { Some(v) }),
    ))(input)
}

// WildcardLiteral = Literal | '*'
pub fn parse_wildcard_literal(input: &str) -> IResult<&str, Option<String>> {
    alt((
        value(None, tag("*")),
        map(parse_literal, Some),
    ))(input)
}

type QueryNeedsField = Box<dyn FnOnce(Option<String>) -> Query>;

// NotListOfValues = Not ListOfValues
//                 | ListOfValues
pub fn parse_not_list_of_values(input: &str) -> IResult<&str, QueryNeedsField> {
    map(pair(
        opt(parse_not),
        parse_list_of_values,
    ), |(not, func)| match not {
        Some(_) => Box::new(move |field| Query::Not {
            query: Box::new(func(field)),
        }),
        None => func,
    })(input)
}

// AndListOfValues = NotListOfValues (Or NotListOfValues)*
pub fn parse_and_list_of_values(input: &str) -> IResult<&str, QueryNeedsField> {
    map(separated_nonempty_list(
        parse_and,
        parse_not_list_of_values,
    ), |mut queries|
            if queries.len() == 1 { queries.swap_remove(0) }
            else { Box::new(move |field: Option<String>| Query::And {
                queries: queries.into_iter().map(|func| func(field.clone())).collect()
            })},
    )(input)
}

// OrListOfValues = AndListOfValues (Or AndListOfValues)*
pub fn parse_or_list_of_values(input: &str) -> IResult<&str, QueryNeedsField> {
    map(separated_nonempty_list(
        parse_or,
        parse_and_list_of_values,
    ), |mut queries|
            if queries.len() == 1 { queries.swap_remove(0) }
            else { Box::new(move |field: Option<String>| Query::Or {
                queries: queries.into_iter().map(|func| func(field.clone())).collect()
            })},
    )(input)
}

// ListOfValues = '(' Space* OrListOfValues Space* ')'
//              | NullableLiteral
pub fn parse_list_of_values(input: &str) -> IResult<&str, QueryNeedsField> {
    alt((
        map(preceded(
            pair(tag("("), multispace0),
            terminated(
                parse_or_list_of_values,
                pair(multispace0, tag(")")),
            )
        ), |func| Box::new(|field| func(field))  as QueryNeedsField),
        map(parse_nullable_literal,
            |value| Box::new(|field| Query::Equal {field, value}) as QueryNeedsField),
    ))(input)
}

// ValueExpression = NullableLiteral
pub fn parse_value_expression(input: &str) -> IResult<&str, Query> {
    map(parse_nullable_literal, |value| Query::Equal { field: None, value })(input)
}

// FieldValueExpression = WildcardLiteral Space* ':' Space* ListOfValues
pub fn parse_field_value_expression(input: &str) -> IResult<&str, Query> {
    map(pair(
        parse_wildcard_literal,
        preceded(
            tuple((multispace0, tag(":"), multispace0)),
            parse_list_of_values,
        )
    ), |(field, func)| func(field))(input)
}

// FieldRangeExpression = WildcardLiteral Space* RangeOperator Space* Literal
pub fn parse_field_range_expression(input: &str) -> IResult<&str, Query> {
    map(tuple((
        parse_wildcard_literal,
        preceded(
            multispace0,
            parse_range_operator,
        ),
        preceded(
            multispace0,
            parse_literal,
        )
    )), |(field, operator, value)| Query::Order {
        field, operator, value,
    })(input)
}

// Expression = FieldRangeExpression
//            | FieldValueExpression
//            | ValueExpression
pub fn parse_expression(input: &str) -> IResult<&str, Query> {
    alt((
        parse_field_range_expression,
        parse_field_value_expression,
        parse_value_expression,
    ))(input)
}

// SubQuery = '(' Space* OrQuery Space* ')' { return query; }
//          | Expression
pub fn parse_sub_query(input: &str) -> IResult<&str, Query> {
    alt((
        preceded(
            pair(tag("("), multispace0),
            terminated(
                parse_or_query,
                pair(multispace0, tag(")"))
            ),
        ),
        parse_expression,
    ))(input)
}

// NotQuery = Not SubQuery
//          | SubQuery
pub fn parse_not_query(input: &str) -> IResult<&str, Query> {
    map(pair(
        opt(parse_not),
        parse_sub_query,
    ), |(not, query)| match not {
        Some(_) => Query::Not { query: Box::new(query) },
        None => query,
    })(input)
}

// AndQuery = NotQuery (And NotQuery)*
pub fn parse_and_query(input: &str) -> IResult<&str, Query> {
    map(separated_nonempty_list(
        parse_and,
        parse_not_query,
    ), |mut queries|
            if queries.len() == 1 { queries.swap_remove(0) }
            else { Query::And { queries } },
    )(input)
}

// OrQuery = AndQuery (Or AndQuery)*
pub fn parse_or_query(input: &str) -> IResult<&str, Query> {
    map(separated_nonempty_list(
        parse_or,
        parse_and_query,
    ), |mut queries|
            if queries.len() == 1 { queries.swap_remove(0) }
            else { Query::Or { queries } },
    )(input)
}

// start = Space* OrQuery? Space*
pub fn parse(input: &str) -> IResult<&str, Option<Query>> {
    all_consuming(preceded(
        multispace0,
        opt(terminated(
            parse_or_query,
            multispace0,
        ))
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Err;
    use nom::error::ErrorKind;

    #[test]
    fn empty_query() {
        assert_eq!(parse(""), Ok(("", None)));
    }

    #[test]
    fn single_query() {
        assert_eq!(parse(" abc "), Ok(("", Some(Query::Equal { field: None, value: "abc".into() }))));
    }

    #[test]
    fn single_or_query() {
        assert_eq!(parse(" abc or def "), Ok(("", Some(Query::Or {
            queries: vec![
                Query::Equal { field: None, value: "abc".into() },
                Query::Equal { field: None, value: "def".into() }
            ],
        }))));
    }

    #[test]
    fn keyword_query() {
        assert_eq!(parse(" or or or "), Err(Err::Error(("or or or ", ErrorKind::Eof))));
    }

    #[test]
    fn single_implicit_or_query() {
        assert_eq!(parse(" abc def "), Ok(("", Some(Query::Or {
            queries: vec![
                Query::Equal { field: None, value: "abc".into() },
                Query::Equal { field: None, value: "def".into() }
            ],
        }))));
    }

    #[test]
    fn single_and_query() {
        assert_eq!(parse(" abc and def "), Ok(("", Some(Query::And {
            queries: vec![
                Query::Equal { field: None, value: "abc".into() },
                Query::Equal { field: None, value: "def".into() }
            ],
        }))));
    }

    #[test]
    fn single_not_query() {
        assert_eq!(parse(" not abc "), Ok(("", Some(Query::Not {
            query: Box::new(Query::Equal { field: None, value: "abc".into() }),
        }))));
    }

    #[test]
    fn multiple_and_or_not_query() {
        assert_eq!(parse(" abc (def or ghi) and jkl not mno"), Ok(("", Some(Query::Or {
            queries: vec![
                Query::Equal { field: None, value: "abc".into() },
                Query::And {
                    queries: vec![
                        Query::Or {
                            queries: vec![
                                Query::Equal { field: None, value: "def".into() },
                                Query::Equal { field: None, value: "ghi".into() },
                            ],
                        },
                        Query::Equal { field: None, value: "jkl".into() }
                    ],
                },
                Query::Not {
                    query: Box::new(Query::Equal { field: None, value: "mno".into() }),
                },
            ],
        }))));
    }

    #[test]
    fn parse_quoted_string() {
        assert_eq!(parse(" \" d\\\"e\\tf \" abc"), Ok(("", Some(Query::Or {
            queries: vec![
                Query::Equal { field: None, value: " d\"e\tf ".into() },
                Query::Equal { field: None, value: "abc".into() },
            ],
        }))))
    }

    #[test]
    fn parse_quoted_string_fail() {
        assert_eq!(
            parse(" \" d\\a\"e\\tf \" abc"),
            Err(Err::Error(("e\\tf \" abc", ErrorKind::Eof)))
        );
    }

    #[test]
    fn parse_quoted_string_fail2() {
        assert_eq!(
            parse(" \" d\\\"e\\tf \" ab\"c"),
            Err(Err::Error(("\"c", ErrorKind::Eof)))
        );
    }

    #[test]
    fn parse_unquoted_string() {
        assert_eq!(
            parse(" anot nota"),
            Ok(("", Some(Query::Or {
                queries: vec![
                    Query::Equal { field: None, value: "anot".into() },
                    Query::Equal { field: None, value: "nota".into() },
                ],
            }))),
        );
    }

    #[test]
    fn parse_unquoted_string_fail1() {
        assert_eq!(
            parse(" an@ot"),
            Err(Err::Error(("@ot", ErrorKind::Eof)))
        );
    }

    #[test]
    fn parse_field_range_expression() {
        assert_eq!(
            parse(" * > 1"),
            Ok(("", Some(Query::Order {
                field: None,
                operator: OrderOperator::Gt,
                value: "1".into(),
            })))
        );
    }

    #[test]
    fn parse_field_value_expression() {
        assert_eq!(
            parse(" a : 1"),
            Ok(("", Some(Query::Equal {
                field: Some("a".to_string()),
                value: "1".into(),
            })))
        );
    }

    #[test]
    fn parse_list_of_fields_expression() {
        assert_eq!(
            parse(" a:(1 or 2 3 and not 4)"),
            Ok(("", Some(Query::Or {
                queries: vec![
                    Query::Equal {
                        field: Some("a".to_string()),
                        value: "1".into(),
                    },
                    Query::Equal {
                        field: Some("a".to_string()),
                        value: "2".into(),
                    },
                    Query::And {
                        queries: vec![
                            Query::Equal {
                                field: Some("a".to_string()),
                                value: "3".into(),
                            },
                            Query::Not {
                                query: Box::new(Query::Equal {
                                    field: Some("a".to_string()),
                                    value: "4".into(),
                                }),
                            },
                        ],
                    },
                ]
            })))
        );
    }
}
