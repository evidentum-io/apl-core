# apl-core

Pure verification library for APL Protocol v1.0 (Anchored Parallax Log) — reference APL-on-ATL profile.

## Crates

- `apl-core` — APL Core verification: claims, frames, pairwise relations, bridges, diagnostics.
- `apl-ai-eval` — reference implementation of the `APL/AI-Eval` vertical profile: frame-bound
  benchmark observations of a model build (`artifact_digest`, runner, grader, benchmark variant
  and split), profile-specific bridge applicability (`runner-equivalence`, `grader-equivalence`,
  `repeatability`) and the canonical demo "The Two MMLU Scores" — two valid scores under one label
  that a verifier refuses to compare without a bridge.

## Documentation

Full documentation is available at:

**https://apl-protocol.org/implementations/apl-core**
**https://apl-protocol.org/implementations/apl-ai-eval**

## License

Apache-2.0
