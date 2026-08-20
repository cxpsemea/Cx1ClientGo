# Cx1ClientGo Task Recipes

This document collects generalized **task patterns** — realistic,
end-to-end scripts that get from "nothing" to "done" for a specific
job — as opposed to the concept demos in `_examples/` (which each
isolate a single API mechanic) or `OBJECT_MODEL.md` (which explains how
platform objects relate to and depend on each other, with no code at
all). If you're unsure what order things need to be created in, read
[`OBJECT_MODEL.md`](OBJECT_MODEL.md) first — this document doesn't
repeat that reasoning.

Each recipe below started life as a pattern seen repeatedly across a
larger set of internal, customer-specific scripts. The code here is
rewritten from scratch to be generic: no customer names, IDs, URLs, or
data values, and no line copied from any non-public source. Every
recipe is a small standalone Go module under `_examples/recipes/` and
was compiled (`go build ./...`) against the current public API before
being written up here.

## 1. Scan lifecycle & result triage

**Problem:** You need "the current findings for project X," but you
don't know up front whether a scan has already run recently or whether
you need to trigger one.

**Reach for this when:** a script's job starts with "make sure this
project has been scanned" rather than "list existing scans" — e.g. a
CI gate, a periodic health check, or a one-off audit of a project that
might be stale.

**Pattern:** get-or-create the project, reuse its latest completed scan
or trigger a new one from a git repo and poll until it finishes, then
pull results and act on a finding (here: attach a triage comment via a
results predicate).

Code: [`recipes/scanandtriage/scanandtriage.go`](recipes/scanandtriage/scanandtriage.go)

## 2. Idempotent hierarchical provisioning + bulk teardown

**Problem:** Onboarding a new team/tenant-consumer means creating a
small tree of dependent objects (an Application, a Group, child groups,
role bindings, an access grant) — and the script needs to be safely
re-runnable (e.g. from CI on every config change) without erroring out
on objects that already exist. The inverse problem — decommissioning —
means deleting a batch of independent resources without waiting on them
one at a time.

**Reach for this when:** you're writing a provisioning/deprovisioning
script that will run more than once, or that manages resources in bulk
where the individual deletions don't depend on each other.

**Pattern:** get-or-create at every step, treating "already exists"
(HTTP 409) as success rather than failure, respecting the dependency
order in [`OBJECT_MODEL.md`](OBJECT_MODEL.md#sequencing-what-needs-to-exist-before-what);
paired with a concurrent teardown (goroutines + `sync.WaitGroup` + an
error channel) for the bulk-delete side.

Code: [`recipes/provisionteam/provisionteam.go`](recipes/provisionteam/provisionteam.go)

## 3. Enrich a list with cached related-resource lookups → report

**Problem:** You need a report that isn't just "list of X" but "list of
X, each with details about the Y it's linked to" — e.g. every project
with its SCM repository and owning application.

**Reach for this when:** the data you need spans two or more resource
types linked by an ID, and many list items are likely to share the same
related resource (so naively resolving it per-item would mean a lot of
redundant API calls).

**Pattern:** bulk-fetch the primary list, then for each item resolve
the related resource by ID through an in-memory `map[id]result` cache —
only fetched once per unique ID — and write the combined rows to CSV.

**Variant:** the same list → resolve → compare shape also underlies
read-only reconciliation/audit checks — "does this preset still include
query X," "does this project's application assignment still match an
external record." Swap the CSV-writing step for a comparison against
an expected value and you get a drift report instead of an export; the
fetch/cache mechanics don't change.

Code: [`recipes/enrichandexport/enrichandexport.go`](recipes/enrichandexport/enrichandexport.go)

## 4. Recursive access resolution across group hierarchies

**Problem:** "Who can actually access this project?" isn't answered by
a single API call — direct Access Assignments can name a User, a
Group, or an OIDC Client, and a Group grant implies access for every
member of that group *and* every member of its nested subgroups.

**Reach for this when:** you're auditing effective access to a resource
rather than just its direct grants.

**Pattern:** fetch direct Access Assignments for the resource, then for
each group-type grant recursively walk subgroups down to individual
users, using a visited-set keyed by group ID to avoid revisiting a
group reachable through more than one parent (which would otherwise
waste calls or, in a cyclic config, recurse forever).

Code: [`recipes/whocanaccess/whocanaccess.go`](recipes/whocanaccess/whocanaccess.go)

## 5. Aggregate metrics across large scan/event history

**Problem:** You need a tenant-wide metric (e.g. "what languages have
we scanned in the last 3 months") computed over more scans than fit on
one API page.

**Reach for this when:** the dataset you're summarizing is large enough
that you'd otherwise have to hand-write an offset/limit loop.

**Pattern:** use the client's `GetX...Filtered(filter, desiredCount)`
convention (see also `ListScans` in the concept demos, which shows the
single-page vs. `GetAll`/`GetX` distinction directly) to pull a large
filtered set in one call, fetch one detail object per item, and fold
the results into an aggregate map.

Code: [`recipes/scanhistorymetrics/scanhistorymetrics.go`](recipes/scanhistorymetrics/scanhistorymetrics.go)

## 6. Batch-download per-item detail to local disk, with dedup + throttle

**Problem:** You need the raw content behind a batch of findings (e.g.
source snippets) mirrored to local disk — for offline review, archival,
or handing off to a tool that expects files rather than API calls.

**Reach for this when:** you're exporting detail content (not just
metadata) for a list of IDs, especially when the same underlying file
is likely to be referenced by more than one finding.

**Pattern:** for each ID, fetch its detail content, skip anything
already downloaded (dedup by filename per scan), write to a mirrored
local directory tree, and pause briefly between items as simple
throttling.

Code: [`recipes/downloadfindingsources/downloadfindingsources.go`](recipes/downloadfindingsources/downloadfindingsources.go)
