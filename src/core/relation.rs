//! Pairwise relation query parsing per `apl-relation-spec.md §3.1`.
//!
//! This module implements structural-and-typing validation for the
//! `RelationQuery` input to the pairwise verifier.  It does **not** perform
//! subset checks against claim `aspect_refs`, or predicate / relation-type
//! matching against receipts — those belong to the 19-step pairwise algorithm
//! in RELATION-1.
//!
//! # Critical contract
//!
//! [`RelationQuery::parse`] returns either a fully structurally-valid
//! [`RelationQuery`] or a [`RelationQueryParseError`] that identifies exactly
//! which invalidity condition was encountered.

use std::collections::HashSet;

use serde_json::Value;

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// Pairwise relation query per `apl-relation-spec.md §3.1`.
///
/// Structural-and-typing validity is guaranteed for every field once this
/// struct is constructed.  Subset and match checks against claim data are
/// performed by RELATION-1 (steps 4–7 of the pairwise algorithm).
///
/// # Ordering
///
/// `left_aspects` and `right_aspects` preserve input ordering.  RELATION-1
/// converts them to sets at check time; the ordering here is retained for
/// deterministic diagnostics only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationQuery {
    /// Non-empty, unique list of aspect identifiers for the left receipt.
    pub left_aspects: Vec<String>,
    /// Non-empty, unique list of aspect identifiers for the right receipt.
    pub right_aspects: Vec<String>,
    /// Required predicate string; non-empty.
    pub predicate: String,
    /// Required relation-type string; non-empty.
    pub relation_type: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Parse errors for [`RelationQuery`].
///
/// Each variant maps to exactly one invalidity condition from
/// `apl-relation-spec.md §3.1`.  RELATION-1 translates these into
/// `FailureClass` and `Diagnostic` entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationQueryParseError {
    /// The input JSON value is not an object.
    QueryNotObject,
    /// The `left_aspects` field is absent.
    LeftAspectsMissing,
    /// The `left_aspects` field is present but invalid: not an array, empty
    /// array, contains a non-string, contains an empty string, or contains
    /// duplicate entries.
    LeftAspectsInvalid,
    /// The `right_aspects` field is absent.
    RightAspectsMissing,
    /// The `right_aspects` field is present but invalid: not an array, empty
    /// array, contains a non-string, contains an empty string, or contains
    /// duplicate entries.
    RightAspectsInvalid,
    /// The `predicate` field is absent.
    PredicateMissing,
    /// The `predicate` field is present but not a non-empty string.
    PredicateInvalid,
    /// The `relation_type` field is absent.
    RelationTypeMissing,
    /// The `relation_type` field is present but not a non-empty string.
    RelationTypeInvalid,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl RelationQuery {
    /// Parse a JSON value into a [`RelationQuery`].
    ///
    /// This method validates only the query itself (types, non-emptiness,
    /// uniqueness).  Subset / match checks against claims are performed by
    /// RELATION-1 in steps 4–7 of the pairwise algorithm.
    ///
    /// # Errors
    ///
    /// Returns a [`RelationQueryParseError`] describing exactly which
    /// invalidity condition was encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::relation::{RelationQuery, RelationQueryParseError};
    /// use serde_json::json;
    ///
    /// let v = json!({
    ///     "left_aspects":  ["accuracy"],
    ///     "right_aspects": ["accuracy"],
    ///     "predicate":     "score",
    ///     "relation_type": "score-delta"
    /// });
    /// let q = RelationQuery::parse(&v).unwrap();
    /// assert_eq!(q.predicate, "score");
    /// assert_eq!(q.relation_type, "score-delta");
    ///
    /// let bad = json!("not-an-object");
    /// assert_eq!(
    ///     RelationQuery::parse(&bad),
    ///     Err(RelationQueryParseError::QueryNotObject)
    /// );
    /// ```
    pub fn parse(v: &Value) -> Result<Self, RelationQueryParseError> {
        use RelationQueryParseError::{
            LeftAspectsMissing, PredicateInvalid, PredicateMissing, QueryNotObject,
            RelationTypeInvalid, RelationTypeMissing, RightAspectsMissing,
        };

        let obj = v.as_object().ok_or(QueryNotObject)?;

        let left_aspects = parse_unique_nonempty_string_array(
            obj.get("left_aspects").ok_or(LeftAspectsMissing)?,
            RelationQueryParseError::LeftAspectsInvalid,
        )?;

        let right_aspects = parse_unique_nonempty_string_array(
            obj.get("right_aspects").ok_or(RightAspectsMissing)?,
            RelationQueryParseError::RightAspectsInvalid,
        )?;

        let predicate = obj
            .get("predicate")
            .ok_or(PredicateMissing)?
            .as_str()
            .ok_or(PredicateInvalid)?
            .to_owned();
        if predicate.is_empty() {
            return Err(PredicateInvalid);
        }

        let relation_type = obj
            .get("relation_type")
            .ok_or(RelationTypeMissing)?
            .as_str()
            .ok_or(RelationTypeInvalid)?
            .to_owned();
        if relation_type.is_empty() {
            return Err(RelationTypeInvalid);
        }

        Ok(Self {
            left_aspects,
            right_aspects,
            predicate,
            relation_type,
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse a JSON value as a non-empty array of unique, non-empty strings.
///
/// Returns `err` if any of the following conditions are violated:
/// - The value is not a JSON array.
/// - The array is empty.
/// - Any element is not a string.
/// - Any element is an empty string.
/// - Any element is a duplicate of a previously seen element.
fn parse_unique_nonempty_string_array(
    v: &Value,
    err: RelationQueryParseError,
) -> Result<Vec<String>, RelationQueryParseError> {
    let arr = v.as_array().ok_or_else(|| err.clone())?;
    if arr.is_empty() {
        return Err(err);
    }
    let mut out = Vec::with_capacity(arr.len());
    let mut seen = HashSet::new();
    for item in arr {
        let s = item.as_str().ok_or_else(|| err.clone())?;
        if s.is_empty() {
            return Err(err.clone());
        }
        if !seen.insert(s.to_owned()) {
            return Err(err.clone());
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> serde_json::Value {
        json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "score-delta"
        })
    }

    #[test]
    fn accepts_minimal() {
        let q = RelationQuery::parse(&base()).unwrap();
        assert_eq!(q.left_aspects, vec!["accuracy".to_owned()]);
        assert_eq!(q.right_aspects, vec!["accuracy".to_owned()]);
        assert_eq!(q.predicate, "score");
        assert_eq!(q.relation_type, "score-delta");
    }

    #[test]
    fn non_object() {
        assert_eq!(
            RelationQuery::parse(&json!("x")),
            Err(RelationQueryParseError::QueryNotObject)
        );
    }

    #[test]
    fn left_aspects_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("left_aspects");
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::LeftAspectsMissing)
        );
    }

    #[test]
    fn left_aspects_empty() {
        let mut v = base();
        v["left_aspects"] = json!([]);
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::LeftAspectsInvalid)
        );
    }

    #[test]
    fn left_aspects_duplicate() {
        let mut v = base();
        v["left_aspects"] = json!(["a", "a"]);
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::LeftAspectsInvalid)
        );
    }

    #[test]
    fn right_aspects_empty_entry() {
        let mut v = base();
        v["right_aspects"] = json!([""]);
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::RightAspectsInvalid)
        );
    }

    #[test]
    fn predicate_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("predicate");
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::PredicateMissing)
        );
    }

    #[test]
    fn predicate_empty() {
        let mut v = base();
        v["predicate"] = json!("");
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::PredicateInvalid)
        );
    }

    #[test]
    fn predicate_not_string() {
        let mut v = base();
        v["predicate"] = json!(42);
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::PredicateInvalid)
        );
    }

    #[test]
    fn relation_type_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("relation_type");
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::RelationTypeMissing)
        );
    }

    #[test]
    fn relation_type_empty() {
        let mut v = base();
        v["relation_type"] = json!("");
        assert_eq!(
            RelationQuery::parse(&v),
            Err(RelationQueryParseError::RelationTypeInvalid)
        );
    }

    #[test]
    fn multiple_aspects_preserve_order() {
        let mut v = base();
        v["left_aspects"] = json!(["a", "b", "c"]);
        let q = RelationQuery::parse(&v).unwrap();
        assert_eq!(
            q.left_aspects,
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
    }
}
