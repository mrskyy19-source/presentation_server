# Presentation Server — Static Vulnerability Scanner API

A lightweight Flask API that performs rule-based static application security testing (SAST) — scanning submitted code snippets for known dangerous patterns and reporting severity-rated findings.

## Overview

`presentation_server.py` exposes a CORS-enabled Flask endpoint that runs a set of regex-based detection rules against incoming code, flagging common vulnerability classes for demonstration or lightweight review purposes.

## Detection rules

Each rule includes an `id`, a regex `pattern`, an optional `context_must_exist` list (additional context keywords required nearby), a `severity`, and a human-readable `description`. Rules seen so far include:

| ID | Severity | Detects |
|---|---|---|
| `NOSQL-INJECTION-001` | CRITICAL | Unsanitized user input (`req.body.*`, `req.query`) passed directly into database query methods (`findOne`, `find`, `update`) |
| `JWT-CONFUSION-002` | HIGH | `jwt.verify(...)` calls missing an explicit `algorithms` array, leaving them open to RS256/HS256 algorithm-confusion attacks |

(Additional rules may follow the same pattern further in the file.)

## Stack

- **Flask** — HTTP API
- **flask-cors** — CORS support for cross-origin requests (e.g. from a frontend/dashboard)
- **hashlib**, **re** — hashing and regex-based pattern matching
- Rules are plain Python dicts, making it straightforward to add new detection patterns

## Setup

```bash
pip install flask flask-cors
```

## Usage

```bash
python presentation_server.py
```

Submit code snippets to the API for scanning; matched rules return their `id`, `severity`, and `description` so findings can be surfaced in a report, dashboard, or live presentation.

## Use case

Built for walkthroughs/demos of common vulnerability classes (injection, broken auth) — useful for security presentations, training material, or as a starting point for a lightweight internal SAST check.

## Disclaimer

This is a pattern-matching demonstration tool, not a substitute for a full SAST/DAST pipeline or manual code review. False positives/negatives are expected; use alongside established security tooling for production codebases.
