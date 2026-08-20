# Using These Docs

Cx1ClientGo is a Go client library for the CheckmarxOne (Cx1) REST API.
The documents in `_examples/` exist so that anyone — a human contributor
or an LLM with no prior training on this library — can write correct,
idiomatic scripts against it without guessing at API shape or getting
object-creation order wrong.

## Where to go

- **Trying to understand how a specific API mechanic works** (e.g. how
  audit sessions work, how report polling works)? Browse the concept
  demos listed in [`index.md`](index.md).
- **Trying to accomplish a specific task** (e.g. "provision a team,"
  "export a CSV of projects with their SCM repos")? Read
  [`RECIPES.md`](RECIPES.md).
- **Confused about what order to create/reference objects in, or how
  platform objects relate to each other**? Read
  [`OBJECT_MODEL.md`](OBJECT_MODEL.md) — no code, just the object graph
  and sequencing rules.

These three layers are deliberately not merged: concept depth, task
patterns, and object relationships are different questions with
different answers, and flattening them loses that.

## Getting started

Every script needs a client, regardless of which layer above answers
the rest of your question:

```go
import (
	"net/http"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

httpClient := &http.Client{}
logger := logrus.New()

cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)
if err != nil {
	logger.Fatalf("Error creating client: %s", err)
}
```

`NewClient` reads connection details and credentials from CLI
flags/environment variables (see
[`AccessManagement`](AccessManagement/AccessManagement.go)). If your
credential comes in a different shape — a raw API key, an existing
access token, an OIDC client ID/secret — see the "Authentication
options" table in [`index.md`](index.md) for the matching constructor.
