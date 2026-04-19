//! APL Claim parsing and typing rules per `apl-spec.md §5`.
//!
//! This module implements structural-and-typing validation for the full
//! `metadata.apl` envelope (`Claim`) and the inner `claim` object
//! (`ClaimInner`).  It does **not** resolve frames, verify aspect linkage, or
//! evaluate relation-layer semantics — those responsibilities belong to
//! `CORE-VERIFY-1` and `RELATION-1`.
//!
//! # Critical contract
//!
//! [`Claim::parse`] returns either a fully structurally-valid [`Claim`] or a
//! [`ClaimParseError`] that maps 1:1 to exactly one `Diagnostic` code from
//! `apl-spec.md §12.3` and exactly one `FailureClass` from `apl-spec.md
//! §10.2`, `§10.3`, or `§10.6`.  `CORE-VERIFY-1` uses this mapping verbatim.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::hash::{parse_hash_string, Hash, Reference};

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// The full parsed `metadata.apl` envelope (`apl-spec.md §5.2`, `§5.3`).
///
/// Structural-and-typing validity is guaranteed for every field once this
/// struct is constructed.  No semantic checks (frame resolution, aspect
/// linkage, relation evaluation) are performed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// APL Core version string; for v0.1 always `"0.1"` (`§5.3`).
    pub version: String,
    /// Required inner claim object.
    pub claim: ClaimInner,
    /// Required frame reference (`§5.3`).
    pub frame_ref: Reference,
    /// Optional bridge references; if present, the `Vec` is non-empty (`§5.10`).
    pub bridge_refs: Option<Vec<Reference>>,
    /// Optional transformation references; if present, the `Vec` is non-empty (`§5.11`).
    pub transformation_refs: Option<Vec<Reference>>,
}

/// The inner `claim` object (`apl-spec.md §5.2`, `§5.5`–`§5.9`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimInner {
    /// Claim kind.  v0.1 admits only [`ClaimKind::Observation`] (`§5.5`).
    pub kind: ClaimKind,
    /// Claim subject (`§5.6`).
    pub subject: Subject,
    /// Non-empty, unique list of aspect identifiers (`§5.8`).
    pub aspect_refs: Vec<String>,
    /// Claim statement (`§5.7`).
    pub statement: Statement,
    /// Optional related frames; if present, the `Vec` is non-empty and
    /// contains unique hashes (`§5.9`).
    pub related_frames: Option<Vec<Hash>>,
}

/// Claim kind discriminant.
///
/// APL v0.1 defines only `observation` (`apl-spec.md §5.5`).  A second
/// variant would require a protocol-level change; the enum makes such a change
/// visible at the call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// The sole kind admitted by v0.1.
    Observation,
}

/// `claim.subject` per `apl-spec.md §5.6`.
///
/// MUST contain at least one of [`id`][`Subject::id`] or
/// [`digest`][`Subject::digest`].  Additional fields (e.g. `type`,
/// `build_id`, `artifact_digest` for AI-Eval) are preserved in
/// [`full`][`Subject::full`] for profile-level access without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Subject identity string; non-empty when present.
    pub id: Option<String>,
    /// Subject content-addressed digest; validated `sha256:<hex>` when present.
    pub digest: Option<Hash>,
    /// Full subject object, including any profile-specific fields.
    pub full: serde_json::Map<String, Value>,
}

/// `claim.statement` per `apl-spec.md §5.7`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Required predicate string; non-empty.
    pub predicate: String,
    /// Required content value; any JSON value is permitted — including `null`
    /// (`§5.7` requires presence, not a specific type).
    pub content: Value,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Claim-parse errors.
///
/// Each variant maps to exactly one `FailureClass` and one `Diagnostic` code
/// in `CORE-VERIFY-1`.  See `apl-spec.md §10.2`, `§10.3`, and `§10.6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimParseError {
    // === ClaimStructureFailure (§10.2) ======================================
    /// `metadata.apl` is absent or not a JSON object (`§9.2`, `§10.2`).
    MetadataAplMissing,

    /// `metadata.apl.version` field is absent (`§5.3`).
    VersionMissing,

    /// `metadata.apl.version` is present but not a JSON string.
    VersionInvalid,

    /// `metadata.apl.version` is a string but names an unsupported version
    /// (`§10.2` "version не поддерживается").
    VersionUnsupported {
        /// The version string that was found.
        got: String,
    },

    /// `claim` field is absent (`§10.2`).
    ClaimMissing,

    /// `claim` field is present but not a JSON object.
    ClaimNotObject,

    /// `claim.kind` is absent or not a JSON string (`§10.2`).
    ClaimKindMissing,

    /// `claim.kind` is a string but is not `"observation"` (`§10.2`).
    ClaimKindUnsupported {
        /// The kind string that was found.
        got: String,
    },

    /// `claim.subject` is absent (`§10.2`).
    SubjectMissing,

    /// `claim.subject` is present but not a JSON object (`§10.2`).
    SubjectInvalid,

    /// `claim.subject` object contains neither `id` nor `digest` (`§10.2`).
    SubjectMissingIdAndDigest,

    /// `claim.subject.id` is present but is not a non-empty string (`§10.2`).
    SubjectIdInvalid,

    /// `claim.subject.digest` is present but fails hash-string parsing (`§10.2`).
    SubjectDigestInvalid,

    /// `claim.aspect_refs` is absent (`§10.2`).
    AspectRefsMissing,

    /// `claim.aspect_refs` is empty, not an array, contains a non-string,
    /// contains an empty string, or contains duplicates (`§10.2`).
    AspectRefsInvalid,

    /// `claim.statement` is absent (`§10.2`).
    StatementMissing,

    /// `claim.statement` is present but not a JSON object or is otherwise
    /// malformed (`§10.2`).
    StatementInvalid,

    /// `claim.statement.predicate` is absent or an empty string (`§10.2`).
    PredicateMissing,

    /// `claim.statement.content` field is absent (`§10.2`).
    ContentMissing,

    // === ReferenceFailure (§10.3) ===========================================
    /// `frame_ref` field is absent (`§10.3`).
    FrameRefMissing,

    /// `frame_ref` is present but fails Reference-object parsing (`§10.3`).
    FrameRefInvalid,

    // === RelationStructureFailure (§10.6) ===================================
    /// `claim.related_frames` is present but invalid (`§10.6`).
    RelatedFramesInvalid,

    /// `bridge_refs` is present but invalid (`§10.6`).
    BridgeRefsInvalid,

    /// `transformation_refs` is present but invalid (`§10.6`).
    TransformationRefsInvalid,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl Claim {
    /// Parse a JSON value that represents `metadata.apl`.
    ///
    /// # Arguments
    ///
    /// * `v` — the `metadata.apl` JSON value already extracted from the
    ///   carrier's `metadata` key.
    ///
    /// # Errors
    ///
    /// Returns a [`ClaimParseError`] describing exactly which invalidity
    /// condition from `apl-spec.md §10` was encountered.  The caller
    /// (`CORE-VERIFY-1`) translates the error into a `FailureClass` and one or
    /// more `Diagnostic` entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::claim::{Claim, ClaimKind};
    /// use serde_json::json;
    ///
    /// let h = format!("sha256:{}", "1".repeat(64));
    /// let v = json!({
    ///     "version": "0.1",
    ///     "claim": {
    ///         "kind": "observation",
    ///         "subject": { "id": "model:acme-gpt-7b-build-42" },
    ///         "aspect_refs": ["accuracy"],
    ///         "statement": {
    ///             "predicate": "score",
    ///             "content": { "value": 0.781 }
    ///         }
    ///     },
    ///     "frame_ref": { "hash": h }
    /// });
    /// let claim = Claim::parse(&v).unwrap();
    /// assert!(matches!(claim.claim.kind, ClaimKind::Observation));
    /// ```
    pub fn parse(v: &Value) -> Result<Self, ClaimParseError> {
        use ClaimParseError::{
            BridgeRefsInvalid, ClaimMissing, FrameRefInvalid, FrameRefMissing, MetadataAplMissing,
            TransformationRefsInvalid, VersionInvalid, VersionMissing, VersionUnsupported,
        };

        let obj = v.as_object().ok_or(MetadataAplMissing)?;

        // version (§5.3)
        let version_v = obj.get("version").ok_or(VersionMissing)?;
        let version_str = version_v.as_str().ok_or(VersionInvalid)?;
        if version_str != "0.1" {
            return Err(VersionUnsupported {
                got: version_str.to_owned(),
            });
        }

        // frame_ref (§5.3, §10.3)
        let frame_ref_v = obj.get("frame_ref").ok_or(FrameRefMissing)?;
        let frame_ref = Reference::parse(frame_ref_v).map_err(|_| FrameRefInvalid)?;

        // claim (§5.3, §5.5–§5.9, §10.2)
        let claim_v = obj.get("claim").ok_or(ClaimMissing)?;
        let claim = parse_claim_inner(claim_v)?;

        // bridge_refs (§5.10, §10.6)
        let bridge_refs =
            parse_optional_reference_array(obj.get("bridge_refs"), BridgeRefsInvalid)?;

        // transformation_refs (§5.11, §10.6)
        let transformation_refs = parse_optional_reference_array(
            obj.get("transformation_refs"),
            TransformationRefsInvalid,
        )?;

        Ok(Self {
            version: version_str.to_owned(),
            claim,
            frame_ref,
            bridge_refs,
            transformation_refs,
        })
    }

    /// Returns `true` iff the claim is cross-frame per `apl-spec.md §5.9`.
    ///
    /// A claim is cross-frame when `claim.related_frames` is present and
    /// contains at least one hash that differs from `frame_ref.hash`.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::claim::Claim;
    /// use serde_json::json;
    ///
    /// let frame_hash = format!("sha256:{}", "1".repeat(64));
    /// let other_hash = format!("sha256:{}", "2".repeat(64));
    ///
    /// let base = json!({
    ///     "version": "0.1",
    ///     "claim": {
    ///         "kind": "observation",
    ///         "subject": { "id": "x" },
    ///         "aspect_refs": ["a"],
    ///         "statement": { "predicate": "p", "content": 1 },
    ///         "related_frames": [other_hash]
    ///     },
    ///     "frame_ref": { "hash": frame_hash }
    /// });
    /// let c = Claim::parse(&base).unwrap();
    /// assert!(c.is_cross_frame());
    /// ```
    #[must_use]
    pub fn is_cross_frame(&self) -> bool {
        let Some(related) = self.claim.related_frames.as_ref() else {
            return false;
        };
        related.iter().any(|h| *h != self.frame_ref.hash)
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn parse_claim_inner(v: &Value) -> Result<ClaimInner, ClaimParseError> {
    use ClaimParseError::{
        AspectRefsMissing, ClaimKindMissing, ClaimKindUnsupported, ClaimNotObject,
        StatementMissing, SubjectMissing,
    };

    let obj = v.as_object().ok_or(ClaimNotObject)?;

    // kind (§5.5)
    let kind_v = obj.get("kind").ok_or(ClaimKindMissing)?;
    let kind_str = kind_v.as_str().ok_or(ClaimKindMissing)?;
    if kind_str != "observation" {
        return Err(ClaimKindUnsupported {
            got: kind_str.to_owned(),
        });
    }

    // subject (§5.6)
    let subject = parse_subject(obj.get("subject").ok_or(SubjectMissing)?)?;

    // aspect_refs (§5.8)
    let aspect_refs = parse_aspect_refs(obj.get("aspect_refs").ok_or(AspectRefsMissing)?)?;

    // statement (§5.7)
    let statement = parse_statement(obj.get("statement").ok_or(StatementMissing)?)?;

    // related_frames (§5.9)
    let related_frames = parse_optional_hash_array(obj.get("related_frames"))?;

    Ok(ClaimInner {
        kind: ClaimKind::Observation,
        subject,
        aspect_refs,
        statement,
        related_frames,
    })
}

fn parse_subject(v: &Value) -> Result<Subject, ClaimParseError> {
    use ClaimParseError::{
        SubjectDigestInvalid, SubjectIdInvalid, SubjectInvalid, SubjectMissingIdAndDigest,
    };

    let obj = v.as_object().ok_or(SubjectInvalid)?;

    let id = match obj.get("id") {
        None | Some(Value::Null) => None,
        Some(val) => {
            let s = val.as_str().ok_or(SubjectIdInvalid)?;
            if s.is_empty() {
                return Err(SubjectIdInvalid);
            }
            Some(s.to_owned())
        }
    };

    let digest = match obj.get("digest") {
        None | Some(Value::Null) => None,
        Some(val) => {
            let s = val.as_str().ok_or(SubjectDigestInvalid)?;
            Some(parse_hash_string(s).map_err(|_| SubjectDigestInvalid)?)
        }
    };

    if id.is_none() && digest.is_none() {
        return Err(SubjectMissingIdAndDigest);
    }

    Ok(Subject {
        id,
        digest,
        full: obj.clone(),
    })
}

fn parse_aspect_refs(v: &Value) -> Result<Vec<String>, ClaimParseError> {
    use ClaimParseError::AspectRefsInvalid;

    let arr = v.as_array().ok_or(AspectRefsInvalid)?;
    if arr.is_empty() {
        return Err(AspectRefsInvalid);
    }

    let mut out = Vec::with_capacity(arr.len());
    let mut seen = HashSet::new();

    for item in arr {
        let s = item.as_str().ok_or(AspectRefsInvalid)?;
        if s.is_empty() {
            return Err(AspectRefsInvalid);
        }
        if !seen.insert(s.to_owned()) {
            return Err(AspectRefsInvalid); // duplicate
        }
        out.push(s.to_owned());
    }

    Ok(out)
}

fn parse_statement(v: &Value) -> Result<Statement, ClaimParseError> {
    use ClaimParseError::{ContentMissing, PredicateMissing, StatementInvalid};

    let obj = v.as_object().ok_or(StatementInvalid)?;

    let predicate_v = obj.get("predicate").ok_or(PredicateMissing)?;
    let predicate = predicate_v.as_str().ok_or(StatementInvalid)?;
    if predicate.is_empty() {
        return Err(StatementInvalid);
    }

    // §5.7: `content` is REQUIRED; value MAY be any JSON (including null).
    if !obj.contains_key("content") {
        return Err(ContentMissing);
    }
    let content = obj["content"].clone();

    Ok(Statement {
        predicate: predicate.to_owned(),
        content,
    })
}

/// Parse an optional array of [`Reference`] objects.
///
/// `None` and JSON `null` are both treated as absent (returns `Ok(None)`).
/// If the value is present it MUST be a non-empty array of valid Reference
/// objects; otherwise `err` is returned.
fn parse_optional_reference_array(
    v: Option<&Value>,
    err: ClaimParseError,
) -> Result<Option<Vec<Reference>>, ClaimParseError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let arr = val.as_array().ok_or_else(|| err.clone())?;
            if arr.is_empty() {
                return Err(err);
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(Reference::parse(item).map_err(|_| err.clone())?);
            }
            Ok(Some(out))
        }
    }
}

/// Parse an optional array of unique hash strings.
///
/// `None` and JSON `null` are both treated as absent (returns `Ok(None)`).
/// If present, the array MUST be non-empty, each entry MUST be a valid
/// `sha256:<hex>` hash string, and entries MUST be unique.
fn parse_optional_hash_array(v: Option<&Value>) -> Result<Option<Vec<Hash>>, ClaimParseError> {
    use ClaimParseError::RelatedFramesInvalid;

    match v {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let arr = val.as_array().ok_or(RelatedFramesInvalid)?;
            if arr.is_empty() {
                return Err(RelatedFramesInvalid);
            }
            let mut out = Vec::with_capacity(arr.len());
            let mut seen = HashSet::new();
            for item in arr {
                let s = item.as_str().ok_or(RelatedFramesInvalid)?;
                let h = parse_hash_string(s).map_err(|_| RelatedFramesInvalid)?;
                if !seen.insert(h) {
                    return Err(RelatedFramesInvalid); // duplicate
                }
                out.push(h);
            }
            Ok(Some(out))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod positive_tests {
    use super::*;
    use serde_json::json;

    fn h(v: u8) -> String {
        format!("sha256:{}", hex::encode([v; 32]))
    }

    fn minimal_claim() -> Value {
        json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "model:acme-gpt-7b-build-42" },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": { "benchmark": "MMLU", "value": 0.781, "unit": "fraction" }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        })
    }

    #[test]
    fn minimal_example_from_spec() {
        let v = minimal_claim();
        let c = Claim::parse(&v).unwrap();
        assert_eq!(c.version, "0.1");
        assert!(matches!(c.claim.kind, ClaimKind::Observation));
        assert_eq!(c.claim.aspect_refs, vec!["accuracy".to_owned()]);
        assert_eq!(c.claim.statement.predicate, "score");
        assert_eq!(c.frame_ref.hash.to_string(), h(0x11));
        assert!(c.bridge_refs.is_none());
        assert!(c.transformation_refs.is_none());
    }

    #[test]
    fn subject_with_digest_only() {
        let mut v = minimal_claim();
        v["claim"]["subject"] = json!({ "digest": h(0x42) });
        let c = Claim::parse(&v).unwrap();
        assert_eq!(c.claim.subject.id, None);
        assert_eq!(c.claim.subject.digest.unwrap().to_string(), h(0x42));
    }

    #[test]
    fn bridge_refs_present() {
        let mut v = minimal_claim();
        v["bridge_refs"] = json!([{ "hash": h(0x22) }]);
        let c = Claim::parse(&v).unwrap();
        assert_eq!(c.bridge_refs.as_ref().unwrap().len(), 1);
        assert_eq!(c.bridge_refs.as_ref().unwrap()[0].hash.to_string(), h(0x22));
    }

    #[test]
    fn related_frames_cross_frame() {
        let mut v = minimal_claim();
        v["claim"]["related_frames"] = json!([h(0x99)]);
        let c = Claim::parse(&v).unwrap();
        assert!(c.is_cross_frame());
    }

    #[test]
    fn related_frames_same_frame() {
        let mut v = minimal_claim();
        v["claim"]["related_frames"] = json!([h(0x11)]);
        let c = Claim::parse(&v).unwrap();
        assert!(!c.is_cross_frame());
    }

    #[test]
    fn content_can_be_null() {
        let mut v = minimal_claim();
        v["claim"]["statement"]["content"] = json!(null);
        let c = Claim::parse(&v).unwrap();
        assert!(c.claim.statement.content.is_null());
    }

    #[test]
    fn content_can_be_array_or_scalar() {
        let mut v = minimal_claim();
        v["claim"]["statement"]["content"] = json!([1, 2, 3]);
        assert!(Claim::parse(&v).is_ok());

        v["claim"]["statement"]["content"] = json!("hello");
        assert!(Claim::parse(&v).is_ok());

        v["claim"]["statement"]["content"] = json!(42);
        assert!(Claim::parse(&v).is_ok());
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;
    use serde_json::json;

    fn h(v: u8) -> String {
        format!("sha256:{}", hex::encode([v; 32]))
    }

    fn base() -> Value {
        json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["a"],
                "statement": { "predicate": "p", "content": 1 }
            },
            "frame_ref": { "hash": h(0x11) }
        })
    }

    #[test]
    fn non_object_root() {
        assert_eq!(
            Claim::parse(&json!("string")),
            Err(ClaimParseError::MetadataAplMissing)
        );
    }

    #[test]
    fn version_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("version");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::VersionMissing));
    }

    #[test]
    fn version_unsupported() {
        let mut v = base();
        v["version"] = json!("0.2");
        assert_eq!(
            Claim::parse(&v),
            Err(ClaimParseError::VersionUnsupported { got: "0.2".into() })
        );
    }

    #[test]
    fn frame_ref_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("frame_ref");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::FrameRefMissing));
    }

    #[test]
    fn frame_ref_invalid_hash() {
        let mut v = base();
        v["frame_ref"]["hash"] = json!("md5:abc");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::FrameRefInvalid));
    }

    #[test]
    fn claim_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("claim");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::ClaimMissing));
    }

    #[test]
    fn claim_kind_missing() {
        let mut v = base();
        v["claim"].as_object_mut().unwrap().remove("kind");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::ClaimKindMissing));
    }

    #[test]
    fn claim_kind_unsupported() {
        let mut v = base();
        v["claim"]["kind"] = json!("prediction");
        assert_eq!(
            Claim::parse(&v),
            Err(ClaimParseError::ClaimKindUnsupported {
                got: "prediction".into()
            })
        );
    }

    #[test]
    fn subject_missing() {
        let mut v = base();
        v["claim"].as_object_mut().unwrap().remove("subject");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::SubjectMissing));
    }

    #[test]
    fn subject_not_object() {
        let mut v = base();
        v["claim"]["subject"] = json!("not-an-object");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::SubjectInvalid));
    }

    #[test]
    fn subject_missing_id_and_digest() {
        let mut v = base();
        v["claim"]["subject"] = json!({ "type": "something-else" });
        assert_eq!(
            Claim::parse(&v),
            Err(ClaimParseError::SubjectMissingIdAndDigest)
        );
    }

    #[test]
    fn subject_id_empty_string() {
        let mut v = base();
        v["claim"]["subject"] = json!({ "id": "" });
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::SubjectIdInvalid));
    }

    #[test]
    fn subject_digest_invalid() {
        let mut v = base();
        v["claim"]["subject"] = json!({ "digest": "not-a-hash" });
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::SubjectDigestInvalid));
    }

    #[test]
    fn aspect_refs_missing() {
        let mut v = base();
        v["claim"].as_object_mut().unwrap().remove("aspect_refs");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::AspectRefsMissing));
    }

    #[test]
    fn aspect_refs_empty() {
        let mut v = base();
        v["claim"]["aspect_refs"] = json!([]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::AspectRefsInvalid));
    }

    #[test]
    fn aspect_refs_duplicate() {
        let mut v = base();
        v["claim"]["aspect_refs"] = json!(["a", "a"]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::AspectRefsInvalid));
    }

    #[test]
    fn aspect_refs_contains_empty() {
        let mut v = base();
        v["claim"]["aspect_refs"] = json!(["a", ""]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::AspectRefsInvalid));
    }

    #[test]
    fn aspect_refs_contains_non_string() {
        let mut v = base();
        v["claim"]["aspect_refs"] = json!(["a", 42]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::AspectRefsInvalid));
    }

    #[test]
    fn statement_missing() {
        let mut v = base();
        v["claim"].as_object_mut().unwrap().remove("statement");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::StatementMissing));
    }

    #[test]
    fn statement_not_object() {
        let mut v = base();
        v["claim"]["statement"] = json!("stringy");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::StatementInvalid));
    }

    #[test]
    fn predicate_missing() {
        let mut v = base();
        v["claim"]["statement"]
            .as_object_mut()
            .unwrap()
            .remove("predicate");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::PredicateMissing));
    }

    #[test]
    fn predicate_empty_string() {
        let mut v = base();
        v["claim"]["statement"]["predicate"] = json!("");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::StatementInvalid));
    }

    #[test]
    fn content_missing() {
        let mut v = base();
        v["claim"]["statement"]
            .as_object_mut()
            .unwrap()
            .remove("content");
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::ContentMissing));
    }

    // §10.6 relation-structure checks

    #[test]
    fn related_frames_empty() {
        let mut v = base();
        v["claim"]["related_frames"] = json!([]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::RelatedFramesInvalid));
    }

    #[test]
    fn related_frames_duplicate() {
        let mut v = base();
        v["claim"]["related_frames"] = json!([h(0x11), h(0x11)]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::RelatedFramesInvalid));
    }

    #[test]
    fn bridge_refs_empty() {
        let mut v = base();
        v["bridge_refs"] = json!([]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::BridgeRefsInvalid));
    }

    #[test]
    fn bridge_refs_invalid_element() {
        let mut v = base();
        v["bridge_refs"] = json!([{ "no_hash_here": true }]);
        assert_eq!(Claim::parse(&v), Err(ClaimParseError::BridgeRefsInvalid));
    }

    #[test]
    fn transformation_refs_invalid_element() {
        let mut v = base();
        v["transformation_refs"] = json!([{ "hash": "md5:abc" }]);
        assert_eq!(
            Claim::parse(&v),
            Err(ClaimParseError::TransformationRefsInvalid)
        );
    }
}

#[cfg(test)]
mod spec_examples {
    use super::*;
    use serde_json::json;

    #[test]
    fn ai_eval_example_from_spec_14_2() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "model:acme-gpt-7b-build-42" },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark": "MMLU",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": {
                "hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "resolver_hint": "https://registry.example/frames/ai-eval/mmlu-v1.json"
            }
        });
        let c = Claim::parse(&v).unwrap();
        assert_eq!(
            c.frame_ref.resolver_hint.as_deref(),
            Some("https://registry.example/frames/ai-eval/mmlu-v1.json")
        );
    }

    #[test]
    fn photojournalism_example_from_spec_14_3() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "asset:photo-2026-04-18-001" },
                "aspect_refs": ["scene-light-capture"],
                "statement": {
                    "predicate": "captured-as",
                    "content": {
                        "format": "raw",
                        "capture_time": "2026-04-18T10:15:30Z"
                    }
                }
            },
            "frame_ref": {
                "hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            }
        });
        assert!(Claim::parse(&v).is_ok());
    }
}
