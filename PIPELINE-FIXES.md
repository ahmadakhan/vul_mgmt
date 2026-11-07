# Pipeline and matching fixes — 21 October 2026

> See also: [AUDIT-PIPELINE-2026-10-29.md](AUDIT-PIPELINE-2026-10-29.md) for pipeline
> scheduling, cancellation and stale-bundle recovery fixes (29 October 2026).

## Corrected behavior

- Every completed run reconciles active inventory against the entire cached CVE corpus.
  The selected time window controls feed ingestion; it no longer hides older cached
  vulnerabilities from newly registered assets.
- Existing findings refresh their vulnerability data, enrichment, evidence and
  applicability while retaining their IDs, audit timeline, operator lifecycle decisions
  and delivery history.
- Correcting an unknown version can promote a review finding to a confirmed match.
  Patching, disabling or removing inventory marks a retained finding `NOT_APPLICABLE`,
  rather than leaving it queued indefinitely. Returning inventory to an affected version
  re-evaluates it without creating a duplicate finding.
- The delivery worker checks current asset/CVE applicability and operator lifecycle
  status before sending a queued advisory. A stale bundle fails without contacting the
  transport. When the delivery worker detects a stale bundle — meaning at least one
  finding is no longer applicable — it marks all sibling outbox jobs as `FAILED` and
  calls `rebuildFromCurrentInventory()` in `pipeline.ts`, which queues an immediate
  pipeline run so the bundle is reconstructed from current matches within the same tick
  cycle. If all jobs in that bundle failed this applicability check and none was
  accepted, the pipeline's `staleBundles` detection clears the `advisoryId` on retained
  findings so `reconcileFindings` re-queues them. Accepted or partially accepted bundles
  are never automatically resent by this recovery path. Explicit provider retries
  remain at least once.
- The delivery staleness signature (`revision()` / `findingRevision()`) covers only
  content-relevant CVE fields that surface in the delivered advisory — `cvss`,
  `cweMatches`, `versionRange`, `remediation`, `cisaKev.isKev` and the other fields
  shared with the pipeline's `matchingCveSignature`. Enrichment and metadata fields
  refreshed independently by feed adapters (EPSS scores, exploit status, source-feed
  attribution, modification timestamps, CPE weakness IDs) are excluded, so a benign
  enrichment refresh no longer produces a false "CVE intelligence changed" failure.
  The finding fingerprint likewise drops `exploitRisk` (derived from those same
  enrichment fields) so the ON-CONFLICT resurrection can correctly match a failed job
  when only scores changed.
- An explicit CPE version and its interval must both match. Unsupported vendor version
  ordering yields review candidates instead of treating an unreliable comparison as
  proof of exclusion. Duplicate CVEs within one correlation input use the latest
  modification date rather than arrival order.
- The daily digest queues its payload through the same `enqueue()` path, so it records
  `findingRevisions` and `cveRevisions` alongside `cveIds` and `includedFindingIds`.
  Without that evidence every daily-digest job would be rejected by the delivery worker
  as a legacy payload.
- The finding fingerprint covers identity and affected system only (`cveId`, asset ID,
  asset name). `matchedCpe` and the free-text `matchingEvidence` are excluded: the CPE
  is the NVD criterion in a pipeline finding but the inventory CPE in a revalidation
  match, and the evidence string embeds the confidence the policy happened to require.
  Including them made `deliverNext` report "inventory or matching evidence changed"
  — and fail the bundle as stale — on a benign difference in spelling or policy, which
  is what produced the `ADV-DAILY_20261029` failure.
- A digest bundle may include findings that are still held for review, because a daily
  digest summarises the last 24 hours. The delivery worker accepts a review-held
  finding in a digest as long as it still matches current inventory; the same finding
  in a non-digest bundle is still refused. Once a transport accepts a bundle, the
  findings it actually carried (`includedFindingIds`) move to dispatched state, so the
  same finding is not re-queued and re-sent every day. Findings belonging to other
  batches of the same advisory are not touched, and an advisory that has any accepted
  batch is not reported `FAILED` because of a later unrelated partial batch.
- Execution pages display the worker's persisted phases, actual durations and distinct
  queue counts. Queueing is not represented as transport acceptance. Reruns report
  current matches rather than claiming retained findings are newly discovered.

## Verification

Six database-backed lifecycle regressions failed before the fixes and passed afterward:
old-cache/new-inventory matching, review promotion, patch/removal invalidation, refreshed
CVE/enrichment, blocked stale delivery and enrichment-only staleness. The tests also cover
stable IDs, preservation of operator decisions, safe bundle rebuilding and duplicate
suppression after transport acceptance. Three additional matching regressions reproduce
explicit-version/range conflicts, unsupported vendor ordering and duplicate arrival order.

The digest path adds one more regression: a finding held by the confidence policy is
included in the daily digest and delivered (transport called once, status `ACCEPTED`,
the finding released for dispatch), while the same held finding in a non-digest bundle
is still refused without contacting the transport.

Final validation: with `TEST_DATABASE_URL` set, **509 of 511 tests passed, zero skips**,
and TypeScript checking (`npm run lint`) passed. The two failures (`password-reset`,
`pipeline-audit-regressions`) abort in schema migration with `42P01 relation "assets" does
not exist` while building `correlation_assets_cpe`; they fail identically with these
changes stashed and are unrelated to them.

A browser-queued run completed against an isolated PostgreSQL test database. It reconciled
the patched fixture to `NOT_APPLICABLE`, retained four historical findings with three
current matches, queued no duplicate deliveries, and displayed the three measured phases
correctly. Screenshot: [pipeline-fix-verification.png](pipeline-fix-verification.png).

No live provider messages were sent. Transport tests use injected acknowledgements.
Applicability is checked immediately before transport; inventory changes after that check
cannot retract an already submitted notification. Historical findings and accepted
advisories remain retained for review.

## Stale-bundle failure reasons

The delivery worker labels why a queued advisory was rejected so the reason is visible in the outbox and in the rebuild error:

- `current inventory no longer matches` — no current asset/CVE pair;
  `rebuildFromCurrentInventory()` clears the advisory binding, `reconcileFindings`
  retains the finding as `NOT_APPLICABLE`, and it is not re-queued.
- `current applicability or confidence policy requires review` — the finding still
  matches, but the workspace confidence policy now holds it as `REVIEW_REQUIRED`
  (for example the threshold was raised from 80% to 90% after the bundle was queued).
  The stale bundle fails, the sibling jobs fail with the same reason and an immediate
  pipeline run is queued. The run reconciles the finding to `REVIEW_REQUIRED` under
  the current policy; because it is neither `QUEUED_FOR_DISPATCH` nor `AUTO_DISPATCHED`
  it is **not** added to a new advisory and the delivery worker never calls the
  transport for it. Restoring a policy that admits the finding (or an operator ruling)
  makes the next run queue it again.
- `CVE intelligence changed`, `a CVE was withdrawn`, `a finding was resolved or
  dismissed`, `inventory or matching evidence changed` — the bundle is stale for that
  specific reason; accepted or partially accepted advisories are never resent
  automatically.

## Fixed (29 October 2026): strict CPE matching bypass for partial wildcard versions

**Severity: High.** Commit `401eba4` added `hasUnescapedCpeWildcard(assetParsed.version)` to
the `assetVersionUnasserted` check in `matchesWatchlistItem` (`src/utils/cpeMatcher.ts`).
This set `unverifiedVersion=true` for **any** partial wildcard version (e.g., `2.*`),
causing `matchCPE` to bypass the version token mismatch check — so an asset CPE version
`2.*` incorrectly matched a vulnerability whose CPE pins version `1.5`. The result was
a false-positive `REVIEW_REQUIRED` finding. When multiple assets shared a non-intersecting
wildcard version, the same CVE appeared N times on the Vulnerabilities page, producing
the reported "duplicate CVEs under review."

The fix narrows `assetVersionUnasserted` to only cover truly missing (`-`) or literal
`*` versions. Partial wildcards (`1.*`, `2.*`, `1.?`) now flow through
`matchComponent`'s normal token comparison:

- Non-intersecting (`2.*` vs `1.5`): `matchComponent` rejects via `globIntersects`
  → **no finding**.
- Potentially intersecting (`1.*` vs `1.5`): `matchComponent` accepts →
  `contextNeedsReview` (via `hasUnescapedCpeWildcard` at line 832) holds it for
  review → `REVIEW_REQUIRED` (70%).
- Literal `*` or missing `-`: `unverifiedVersion` bypass applies → `REVIEW_REQUIRED`
  (70%).

The companion `hasUnescapedCpeWildcard` check in `contextNeedsReview` ensures
overlapping wildcards are still correctly identified as review candidates. The
evidence string for review findings without a version range no longer incorrectly
states "(90% confidence)" — it now reads "(70% confidence)".

### Regression tests

- `non-intersecting wildcard asset version does not match a concrete vuln version` — verifies `matchCPE` and `matchesWatchlistItem` reject `2.*` vs `1.5` while accepting `1.*` vs `1.5` as `REVIEW_REQUIRED`.
- `non-intersecting wildcard assets do not produce duplicate CVE findings` — verifies the pipeline produces zero findings when three assets with `2.*` face a CVE pinned to `1.5`.

All 44 audit tests and 382 unit tests pass; TypeScript typecheck is clean.
