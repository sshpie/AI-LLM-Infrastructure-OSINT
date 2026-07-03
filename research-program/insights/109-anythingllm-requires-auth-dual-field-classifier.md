# Insight #109: Single-field auth check inflates open rate — AnythingLLM RequiresAuth + MultiUserMode

**Survey:** Cat-AnythingLLM, 2026-07-02
**Finding type:** Methodology / classifier error
**Impact:** False positive rate 69.6% when checking RequiresAuth alone

## Statement

For AnythingLLM, checking `RequiresAuth=false` alone is an insufficient unauthenticated classifier.
The correct open condition is `RequiresAuth=false AND MultiUserMode=false`.

`MultiUserMode=true` enforces independent login via a separate middleware chain regardless of `RequiresAuth`.
A host with `RequiresAuth=false, MultiUserMode=true` is **gated**, not open.

## Evidence

Cat-07 (2026-05-31) reported 20/28 = 71% unauth using `RequiresAuth` only.

Cat-AnythingLLM (2026-07-02, 56 live hosts, correct dual-field method):
- Truly open (RequiresAuth=false AND MultiUserMode=false): 1/56 = 1.8%
- Multi-user gated (MultiUserMode=true): 2/56 = 3.6%
- Auth-on (RequiresAuth=true): 52/56 = 92.9%

The corrected open rate is 1.8%, not 71%. The 69-point gap is entirely from misclassifying
MultiUserMode=true instances as open.

## Source

From `server/utils/middleware/validatedRequest.js` (single-user path):
```js
if (!process.env.AUTH_TOKEN || !process.env.JWT_SECRET) { next(); return; }
```
Single-user bypass fires when AUTH_TOKEN or JWT_SECRET is absent.

From `server/utils/middleware/multiUserProtected.js` (multi-user path):
```js
// validates JWT regardless of AUTH_TOKEN state
// MultiUserMode=true routes always hit this middleware
```

Both code paths exist simultaneously. Setting MultiUserMode creates an independent auth wall
that validatedRequest.js never touches.

## Implication for aimap fingerprint

The current aimap AnythingLLM enumerator reports `auth_status: "unknown"` because it doesn't
cross-check MultiUserMode from the /api/setup-complete response. Enhancement needed:
- Read both `RequiresAuth` and `MultiUserMode` from the parsed JSON
- Set `auth_status: "open"` only when BOTH are false
- Set `auth_status: "multi_user_gated"` when MultiUserMode=true
- Set `auth_status: "authenticated"` when RequiresAuth=true

## Generalization

This class of error (single-field auth check ignoring secondary enforcement) applies anywhere
a platform has two independent gatekeeping mechanisms. The `RequiresAuth` field describes
the single-user path; `MultiUserMode` describes an entirely separate auth infrastructure.
Checking only one is guaranteed to inflate the open rate whenever multi-user adoption is high.

**Rule:** When a platform has multiple auth paths, require ALL to be permissive before
classifying a host as open. One bypass condition ≠ platform bypassed.
