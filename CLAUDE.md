# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Cx1ClientGo** is a CheckmarxOne REST API client library written in Go. It provides a programmatic interface to interact with the CheckmarxOne (Cx1) security platform, including functionality for managing projects, scans, audit events, results, users, groups, and more.

- **Module path**: `github.com/cxpsemea/Cx1ClientGo`
- **Type**: Go library/package (not an application)
- **Go version**: 1.25.0
- **Key dependencies**:
  - `github.com/golang-jwt/jwt/v4` - JWT token handling
  - `github.com/google/go-querystring` - Query string encoding
  - `golang.org/x/exp` - Experimental features

## Writing Scripts That Use Cx1ClientGo

If the task involves *consuming* Cx1ClientGo (writing a script/tool that
calls this library), not modifying the library itself, read
[`_examples/USAGE.md`](_examples/USAGE.md) first. It routes to concept
demos, task recipes, and the platform object model — all written to
prevent hallucinated API shape or object-creation order.

## Building and Testing

### Build Commands

```bash
# Build as library (no output, just checks for compilation errors)
go build ./...

# Build the examples
go build -o _examples/AccessManagement/AccessManagement _examples/AccessManagement/AccessManagement.go
go build -o _examples/ListScans/ListScans _examples/ListScans/ListScans.go
```

### Testing

```bash
# Run all tests
go test ./...

# Run a specific test
go test -run TestParseQueryRun_NilValue ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...
```

### Linting and Code Quality

```bash
# Format code (Go standard)
go fmt ./...

# Check for vet errors
go vet ./...

# Get module dependencies info
go mod tidy
go mod verify
```

## Architecture and Design

### Single-Package Design
The entire codebase is a single Go package named `Cx1ClientGo`. All functionality is exposed through methods on the `Cx1Client` struct. This keeps the API surface clean and all client logic contained.

### Client Initialization Pattern
The client is initialized through several factory functions that encapsulate different authentication methods:

- **`NewClient()`** - Reads credentials from command-line flags (useful for CLI tools)
- **`NewOAuthClient()` / `NewOAuthClientWithToken()`** - OAuth Client ID + Secret
- **`NewAPIKeyClient()` / `NewAPIKeyClientWithToken()`** - API Key authentication  
- **`NewTokenClient()`** - Direct access token (for zero-trust workflows)
- **`NewClientWithOptions()`** - Full configuration control

All constructors ultimately call `NewClientWithOptions()` which validates configuration, initializes the client, and optionally performs version checks and permission gathering.

### HTTP Request Flow
HTTP requests follow a layered pattern:
1. High-level API methods (e.g., `GetProjectByID()`) - business logic
2. `sendRequestInternal()` / `sendRequestRaw()` - low-level HTTP handling
3. `createRequest()` - builds HTTP request with auth headers
4. `refreshAccessToken()` - manages token lifecycle (auto-refreshes 30 seconds before expiry)
5. `handleHTTPResponse()` - manages retries and error handling

### Authentication
Token handling is automatic:
- Client stores `AccessToken` and `Expiry` in `Cx1ClientAuth`
- Before each request, `refreshAccessToken()` checks if token is expiring soon
- Supports both API Key (refresh_token grant) and OAuth Client Credentials flows
- JWT claims are parsed to extract user info and tenant details

### Version-Aware Behavior
The client parses the Cx1 version during initialization and conditionally adjusts API usage based on version compatibility (see `InitializeClient()` and version checks like `version.CheckCxOne()`).

## File Organization

Files are organized by functional domain. Each domain typically has:
- A main file with core functionality (e.g., `audit.go`)
- Version-specific variants when APIs differ (e.g., `audit_v310.go`)
- Type definitions alongside implementation
- Optional test files (e.g., `audit_test.go`)

### Core Infrastructure
- **types.go** - All core struct definitions (Cx1Client, Cx1Claims, Logger interface, etc.)
- **cx1client.go** - Client constructors and initialization
- **cx1clientconfiguration.go** - Configuration validation and defaults
- **plumbing.go** - HTTP request/response handling, token management, retries
- **util.go** - Common utility functions

### Functional Modules
- **audit.go** / **audit_v310.go** - Audit session queries and results
- **access.go** - Access control and role management
- **projects.go** / **projectsoverview.go** - Project operations
- **scans.go** / **scanschedule.go** - Scan creation and scheduling
- **results.go** / **sastresults.go** - Scan results and findings
- **queries.go** / **queries_v310.go** - Query management and compilation
- **clients.go** - OIDC client and service account management
- **users.go** / **user.go** - User and group management
- **groups.go** - Group operations
- **applications.go** / **applicationsoverview.go** - Application management
- **policies.go** - Policy management
- **presets.go** / **presets_v330.go** - Preset and query collection management
- **reports.go** - Report generation and download
- **analytics.go** - Analytics data retrieval
- **migration.go** - Data migration utilities
- **iam.go** - IAM-related operations
- **misc.go** - Miscellaneous APIs (version, system info)
- **cx1cache.go** - Caching utilities
- **configurationsettings.go** - Platform configuration
- **cxlink.go** - CxLink integration
- **iacquerycollection.go** / **sastquerycollection.go** - Query collection operations
- **scm.go** - Source control management integration
- **lists.go** - List/enum operations
- **auditevent.go** - Audit event types and operations

### Examples
The `_examples/` directory contains complete working examples:
- **AccessManagement/** - Managing users, groups, and roles
- **ListScans/** - Querying scan history
- **MigrationImport/** - Data migration workflows
- **QueryManipulation/** - Creating and editing SAST queries

## Key Patterns and Conventions

### Method Naming
- **Get** methods fetch data (e.g., `GetProjectByID()`, `GetScanByID()`)
- **Create** methods create resources (e.g., `CreateProject()`, `CreateGroup()`)
- **Update** methods modify resources (e.g., `UpdateProject()`)
- **Delete** methods remove resources (e.g., `DeleteProject()`)
- **Request** methods trigger async operations (e.g., `RequestNewReportByID()`)
- **Poll** methods check async operation status (e.g., `GetReportStatusByID()`)

### Pagination
Many list operations support pagination via the `PaginationSettings` configuration. When fetching large result sets, the client automatically uses configured limits and offsets.

### Filter and Query Types
- Most list operations accept a `BaseFilter` or domain-specific filter struct
- Filters use `url` struct tags for query string encoding
- Offset-based pagination with configurable limits

### Error Handling
- Errors return as the second return value
- Network errors are automatically retried (with backoff)
- HTTP error codes are returned as errors
- Some operations document that they may return partial results with an error (see `GetScanResultsByID()`)

### Logger Interface
The `Logger` interface defines six logging levels: Tracef, Debugf, Infof, Warnf, Errorf, Fatalf. Most client operations don't log by default; enable Trace level for detailed API request/response logging.

### Polling Operations
Many operations are async. The typical pattern is:
1. Trigger the operation (returns an ID or status object)
2. Poll the status using a Get method
3. Configure polling timeout/delays via `ClientVars` in config

Common polling operations: scans, reports, migrations, audit compilation, language detection.

## Testing Approach

The repository has minimal test coverage (only a few test files). Tests are unit tests that validate parsing and logic:
- `audit_test.go` - Tests for query result parsing
- `sastquerycollection_test.go` - Tests for query collection operations

To run or add tests:
```bash
go test -v ./...
```

Tests should use the standard Go testing package. When adding tests, follow the pattern of existing tests (table-driven when appropriate).

## Development Notes

### Deprecations
Some functions are deprecated when APIs change in newer Cx1 versions. Deprecation warnings are emitted at Warn log level. Check git history and comments for context on deprecated functions.

### Version Compatibility
The client is designed to work with multiple Cx1 versions. When making changes:
- Check if the API changed between versions (see version-specific files like `audit_v310.go`)
- Version checks in `InitializeClient()` show conditional logic patterns
- The `VersionInfo` type holds parsed version information

### Authentication State
The client maintains mutable state:
- `AccessToken` and `Expiry` update automatically on each request
- User info (`Userinfo`, `claims`, `user`) is populated during initialization
- Calling code can retrieve this state via public getters

### Public vs Internal
- Exported types/functions start with uppercase (Go convention)
- Internal helpers start with lowercase
- The `cx1*` file prefix indicates they're part of the client infrastructure layer

## Common Workflows

### Creating a CLI Tool
Use `NewClient()` with the standard `flag` package to accept command-line arguments:
```bash
go run . -cx1 https://eu.ast.checkmarx.net -iam https://eu.iam.checkmarx.net -tenant mytenantname -apikey <key>
```

### Consuming as a Library
Import and use one of the specific constructors:
```go
import "github.com/cxpsemea/Cx1ClientGo"

client, err := Cx1ClientGo.NewOAuthClient(httpClient, baseURL, iamURL, tenant, clientID, secret, logger)
projects, err := client.GetProjects()
```

### Handling Token Expiry
Token refresh is automatic before each request (30 second buffer). If you need to serialize/restore a client across process boundaries, extract and restore `AccessToken` and `Expiry` from the auth config.

## Common Issues and Gotchas

1. **Token Expiry**: The client auto-refreshes tokens. If you're making many requests, ensure your base credentials (API key, client secret) remain valid.

2. **Pagination**: Large result sets are paginated. When consuming list results, check if more data exists and paginate if needed using the limit/offset pattern.

3. **Async Operations**: Report generation, scans, migrations, and audits are asynchronous. Always poll for completion and handle timeouts.

4. **Version Differences**: The same API endpoint may return different data shapes in different Cx1 versions. The client handles known differences; if you hit version-specific bugs, check the version-specific files.

5. **Logger Implementation**: Provide a logger that implements the `Logger` interface. If you pass `nil`, the code will panic. Standard practice is to use `github.com/sirupsen/logrus` or a simple wrapper.

6. **HTTP Client Customization**: Pass a pre-configured `http.Client` to the constructor to control timeouts, proxies, TLS settings, and retries (though the Cx1Client also implements its own retries).
