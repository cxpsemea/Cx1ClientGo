package Cx1ClientGo

import (
	"testing"
)

// makeQuery builds a SASTQuery with the given level/id/lang/group/name, leaving other fields zero.
func makeQuery(level, levelID, language, group, name string, queryID uint64) SASTQuery {
	return SASTQuery{
		QueryID:  queryID,
		Level:    level,
		LevelID:  levelID,
		Language: language,
		Group:    group,
		Name:     name,
	}
}

// collectionWith builds a SASTQueryCollection from the given queries.
func collectionWith(queries ...SASTQuery) SASTQueryCollection {
	var qc SASTQueryCollection
	for _, q := range queries {
		qc.AddQuery(q)
	}
	return qc
}

// TestGetClosestQueryByLevelAndName verifies the 4-level priority fallback chain:
// Project > Application > Tenant > Product
//
// Application-level overrides come from project-level API responses and are stored
// with levelID = projID (the same project UUID), not a separate application UUID.
// The level field ("Application") is what distinguishes them from project overrides.
func TestGetClosestQueryByLevelAndName(t *testing.T) {
	const (
		lang   = "CSharp"
		group  = "General"
		name   = "SQL_Injection"
		projID = "proj-uuid"
	)

	productQ := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, lang, group, name, 1)
	tenantQ := makeQuery(AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, lang, group, name, 2)
	appQ := makeQuery(AUDIT_QUERY.APPLICATION, projID, lang, group, name, 3) // levelID = projID, not a separate app UUID
	projectQ := makeQuery(AUDIT_QUERY.PROJECT, projID, lang, group, name, 4)

	t.Run("only product exists - all levels return product", func(t *testing.T) {
		qc := collectionWith(productQ)
		for _, level := range []struct{ level, levelID string }{
			{AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT},
			{AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT},
			{AUDIT_QUERY.APPLICATION, projID},
			{AUDIT_QUERY.PROJECT, projID},
		} {
			q := qc.GetClosestQueryByLevelAndName(level.level, level.levelID, lang, group, name)
			if q == nil {
				t.Errorf("level %v: expected product query, got nil", level.level)
			} else if q.QueryID != productQ.QueryID {
				t.Errorf("level %v: expected product query (ID %d), got ID %d", level.level, productQ.QueryID, q.QueryID)
			}
		}
	})

	t.Run("product and tenant exist - lower levels fall back to tenant", func(t *testing.T) {
		qc := collectionWith(productQ, tenantQ)

		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, lang, group, name); q == nil || q.QueryID != productQ.QueryID {
			t.Errorf("product level: expected product query")
		}
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, lang, group, name); q == nil || q.QueryID != tenantQ.QueryID {
			t.Errorf("tenant level: expected tenant query")
		}
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.APPLICATION, projID, lang, group, name); q == nil || q.QueryID != tenantQ.QueryID {
			t.Errorf("application level (no app override): expected fallback to tenant query")
		}
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PROJECT, projID, lang, group, name); q == nil || q.QueryID != tenantQ.QueryID {
			t.Errorf("project level (no project override): expected fallback to tenant query")
		}
	})

	t.Run("application override exists - app level returns it, project falls back to it", func(t *testing.T) {
		qc := collectionWith(productQ, tenantQ, appQ)

		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.APPLICATION, projID, lang, group, name); q == nil || q.QueryID != appQ.QueryID {
			t.Errorf("application level: expected application query")
		}
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PROJECT, projID, lang, group, name); q == nil || q.QueryID != appQ.QueryID {
			t.Errorf("project level (no project override): expected fallback to application query")
		}
	})

	t.Run("all levels exist - each level returns its own override", func(t *testing.T) {
		qc := collectionWith(productQ, tenantQ, appQ, projectQ)

		cases := []struct {
			level   string
			levelID string
			wantID  uint64
		}{
			{AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, productQ.QueryID},
			{AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, tenantQ.QueryID},
			{AUDIT_QUERY.APPLICATION, projID, appQ.QueryID},
			{AUDIT_QUERY.PROJECT, projID, projectQ.QueryID},
		}
		for _, c := range cases {
			q := qc.GetClosestQueryByLevelAndName(c.level, c.levelID, lang, group, name)
			if q == nil {
				t.Errorf("level %v: expected query, got nil", c.level)
			} else if q.QueryID != c.wantID {
				t.Errorf("level %v: expected ID %d, got %d", c.level, c.wantID, q.QueryID)
			}
		}
	})

	t.Run("unknown language returns nil", func(t *testing.T) {
		qc := collectionWith(productQ)
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Unknown", group, name); q != nil {
			t.Errorf("expected nil for unknown language, got query ID %d", q.QueryID)
		}
	})

	t.Run("unknown group returns nil", func(t *testing.T) {
		qc := collectionWith(productQ)
		if q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, lang, "UnknownGroup", name); q != nil {
			t.Errorf("expected nil for unknown group, got query ID %d", q.QueryID)
		}
	})

	t.Run("application override for different project does not satisfy this project lookup", func(t *testing.T) {
		otherProjAppQ := makeQuery(AUDIT_QUERY.APPLICATION, "other-proj-uuid", lang, group, name, 99)
		qc := collectionWith(productQ, tenantQ, otherProjAppQ)

		q := qc.GetClosestQueryByLevelAndName(AUDIT_QUERY.PROJECT, projID, lang, group, name)
		if q == nil || q.QueryID != tenantQ.QueryID {
			t.Errorf("project level: expected fallback to tenant (not other project's app override), got %v", q)
		}
	})
}

// TestAddQuery_MergeVsAppend verifies that AddQuery merges duplicate entries rather than duplicating them,
// and correctly creates new language/group entries when needed.
func TestAddQuery_MergeVsAppend(t *testing.T) {
	t.Run("adding same query twice does not create duplicate", func(t *testing.T) {
		qc := collectionWith(
			makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
			makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
		)
		if n := qc.GetQueryCount(); n != 1 {
			t.Errorf("expected 1 query after adding same query twice, got %d", n)
		}
	})

	t.Run("same query name at different levels creates separate entries", func(t *testing.T) {
		qc := collectionWith(
			makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
			makeQuery(AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, "Java", "Injection", "SQL_Injection", 11),
		)
		if n := qc.GetQueryCount(); n != 2 {
			t.Errorf("expected 2 queries for different levels, got %d", n)
		}
	})

	t.Run("query in new language creates new language entry", func(t *testing.T) {
		qc := collectionWith(
			makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
			makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "CSharp", "Injection", "SQL_Injection", 20),
		)
		if qc.GetQueryLanguageByName("Java") == nil {
			t.Error("expected Java language to exist")
		}
		if qc.GetQueryLanguageByName("CSharp") == nil {
			t.Error("expected CSharp language to exist")
		}
		if n := qc.GetQueryCount(); n != 2 {
			t.Errorf("expected 2 queries total, got %d", n)
		}
	})

	t.Run("language lookup is case-insensitive", func(t *testing.T) {
		qc := collectionWith(makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10))
		if qc.GetQueryLanguageByName("java") == nil {
			t.Error("expected case-insensitive language lookup to succeed")
		}
		if qc.GetQueryLanguageByName("JAVA") == nil {
			t.Error("expected uppercase language lookup to succeed")
		}
	})
}

// TestAddQuery_MergesFields verifies that when a matching query already exists,
// MergeQuery fills in zero-value fields from the incoming query without overwriting populated ones.
func TestAddQuery_MergesFields(t *testing.T) {
	existing := SASTQuery{
		QueryID:  10,
		Level:    AUDIT_QUERY.PRODUCT,
		LevelID:  AUDIT_QUERY.PRODUCT,
		Language: "Java",
		Group:    "Injection",
		Name:     "SQL_Injection",
		Path:     "existing/path.cs",
		EditorKey: "",
	}
	incoming := SASTQuery{
		QueryID:   10,
		Level:     AUDIT_QUERY.PRODUCT,
		LevelID:   AUDIT_QUERY.PRODUCT,
		Language:  "Java",
		Group:     "Injection",
		Name:      "SQL_Injection",
		Path:      "",        // zero — should not overwrite existing
		EditorKey: "new-key", // non-zero — should fill in the blank
	}

	var qc SASTQueryCollection
	qc.AddQuery(existing)
	qc.AddQuery(incoming)

	if n := qc.GetQueryCount(); n != 1 {
		t.Fatalf("expected 1 query after merge, got %d", n)
	}
	q := qc.GetQueryByID(10)
	if q == nil {
		t.Fatal("expected to find query by ID 10")
	}
	if q.Path != "existing/path.cs" {
		t.Errorf("existing path should be preserved, got %q", q.Path)
	}
	if q.EditorKey != "new-key" {
		t.Errorf("blank EditorKey should be filled by merge, got %q", q.EditorKey)
	}
}

// TestAddCollection verifies that AddCollection adds new queries from the source
// that are not present in the destination.
func TestAddCollection(t *testing.T) {
	base := collectionWith(
		makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
	)
	extra := collectionWith(
		makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10), // already in base
		makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "XSS", 11),           // new
	)

	base.AddCollection(&extra)

	if n := base.GetQueryCount(); n != 2 {
		t.Errorf("expected 2 queries after AddCollection, got %d", n)
	}
	if base.GetQueryByID(11) == nil {
		t.Error("expected new query (XSS, ID 11) to be added")
	}
}

// TestUpdateFromCollection verifies that UpdateFromCollection updates existing queries
// but does NOT add queries that aren't already in the destination.
func TestUpdateFromCollection(t *testing.T) {
	base := collectionWith(
		makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10),
	)

	updates := collectionWith(
		func() SASTQuery {
			q := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10)
			q.EditorKey = "updated-key"
			return q
		}(),
		makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "XSS", 11), // not in base
	)

	base.UpdateFromCollection(&updates)

	if n := base.GetQueryCount(); n != 1 {
		t.Errorf("UpdateFromCollection should not add new queries; expected 1, got %d", n)
	}
	q := base.GetQueryByID(10)
	if q == nil {
		t.Fatal("expected existing query to still exist")
	}
	if q.EditorKey != "updated-key" {
		t.Errorf("expected existing query to be updated, EditorKey = %q", q.EditorKey)
	}
}

// TestGetDiffs verifies the diff logic between two collections.
func TestGetDiffs(t *testing.T) {
	qA := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10)
	qB := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "XSS", 11)

	t.Run("identical collections have no diffs", func(t *testing.T) {
		c1 := collectionWith(qA, qB)
		c2 := collectionWith(qA, qB)
		missing, extra := c1.GetDiffs(&c2)
		if missing.GetQueryCount() != 0 {
			t.Errorf("expected 0 missing, got %d", missing.GetQueryCount())
		}
		if extra.GetQueryCount() != 0 {
			t.Errorf("expected 0 extra, got %d", extra.GetQueryCount())
		}
	})

	t.Run("c2 has extra query", func(t *testing.T) {
		c1 := collectionWith(qA)
		c2 := collectionWith(qA, qB)
		missing, extra := c1.GetDiffs(&c2)
		// from c1's perspective: qB is in c2 but not c1 → missing
		if missing.GetQueryCount() != 1 {
			t.Errorf("expected 1 missing query, got %d", missing.GetQueryCount())
		}
		if extra.GetQueryCount() != 0 {
			t.Errorf("expected 0 extra queries, got %d", extra.GetQueryCount())
		}
	})

	t.Run("c1 has extra query", func(t *testing.T) {
		c1 := collectionWith(qA, qB)
		c2 := collectionWith(qA)
		missing, extra := c1.GetDiffs(&c2)
		if missing.GetQueryCount() != 0 {
			t.Errorf("expected 0 missing queries, got %d", missing.GetQueryCount())
		}
		if extra.GetQueryCount() != 1 {
			t.Errorf("expected 1 extra query, got %d", extra.GetQueryCount())
		}
	})
}

// TestIsSubset verifies that IsSubset correctly identifies whether all queries in one
// collection exist in another.
func TestIsSubset(t *testing.T) {
	qA := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10)
	qB := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "XSS", 11)

	full := collectionWith(qA, qB)
	partial := collectionWith(qA)
	empty := SASTQueryCollection{}

	if !partial.IsSubset(&full) {
		t.Error("partial should be a subset of full")
	}
	if full.IsSubset(&partial) {
		t.Error("full should not be a subset of partial")
	}
	if !empty.IsSubset(&partial) {
		t.Error("empty collection should be a subset of any collection")
	}
}

// TestGetCustomQueryCollection verifies that only custom (non-product) queries are returned.
func TestGetCustomQueryCollection(t *testing.T) {
	productQ := makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10)
	tenantQ := makeQuery(AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, "Java", "Injection", "SQL_Injection", 11)

	productQ.Custom = false
	tenantQ.Custom = true

	qc := collectionWith(productQ, tenantQ)
	custom := qc.GetCustomQueryCollection()

	if custom.GetQueryCount() != 1 {
		t.Errorf("expected 1 custom query, got %d", custom.GetQueryCount())
	}
	if custom.GetQueryByID(tenantQ.QueryID) == nil {
		t.Error("expected tenant query in custom collection")
	}
	if custom.GetQueryByID(productQ.QueryID) != nil {
		t.Error("product query should not appear in custom collection")
	}
}

// TestGetQueryByID_ZeroIDReturnsNil verifies the guard against zero-ID lookups.
func TestGetQueryByID_ZeroIDReturnsNil(t *testing.T) {
	qc := collectionWith(makeQuery(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, "Java", "Injection", "SQL_Injection", 10))
	if qc.GetQueryByID(0) != nil {
		t.Error("GetQueryByID(0) should return nil")
	}
}
