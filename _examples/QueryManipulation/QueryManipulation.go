// QueryManipulation demonstrates the SAST and IAC query-audit object model - Web-Audit
// Sessions, query collections, and creating/editing/running custom queries at each
// override level:
//   - get or create a test Project inside a test Application, and make sure it has at
//     least one completed scan to audit (reusing the latest one, or running a new one)
//   - open a Web-Audit session against that scan/project (GetAuditSessionByID) - all
//     query editing happens through this session, and it must be kept alive
//     (AuditSessionKeepAlive) between long-running operations or it will expire
//   - fetch the query collection and list existing custom (non-Cx-level) queries
//   - create a query override at each of the three levels queries can live at - Tenant
//     ("corp"), Application, and Project - each overriding the same base query, plus
//     one brand-new Tenant-level query
//   - edit an override's source and metadata (severity) after creating it
//   - run a query (first with a deliberately broken source to see the error shape,
//     then with valid source) and fetch the results/vulnerabilities it produced
//   - delete every override/query created, then close the audit session
//
// The whole sequence is done twice: once for SAST (makeSASTQueries) and once for IAC
// (makeIACQueries). The two halves are structurally identical - SAST additionally
// demonstrates running a query and inspecting its results, which the IAC audit API
// does not expose in the same way.
package main

import (
	"net/http"
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

var iacSrc string = `package Cx
CxPolicy[result] {
result := {}
}`

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)
	logger.Infof("Starting")

	httpClient := &http.Client{}
	cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	logger.Infof("Retrieving or creating test-project inside application test-application")

	// Get-or-create the Application-scoped Project this example audits.
	project, _, err := cx1client.GetOrCreateProjectInApplicationByName("test-project", "test-application")
	if err != nil {
		logger.Fatalf("Error getting or creating project 'test-project' under application 'test-application': %s", err)
	}

	// A Web-Audit session needs a completed scan to attach to - reuse the latest one if any exists.
	logger.Infof("Retrieving last successful scan for %v", project.String())
	lastscans, err := cx1client.GetLastScansByStatusAndID(project.ProjectID, 1, []string{"Completed"})
	var lastscan Cx1ClientGo.Scan

	if err == nil && len(lastscans) > 0 {
		lastscan = lastscans[0]
	} else {
		if err != nil {
			logger.Warnf("Error getting last completed scan: %s", err)
		} else {
			logger.Warnf("No successfully completed scans have been run for this project")
		}
		// No usable prior scan - trigger and wait for a fresh one instead.
		logger.Infof("Running a new scan")

		scanConfigSet := Cx1ClientGo.ScanConfigurationSet{}
		scanConfigSet.AddConfig("sast", "", "")
		scanConfigSet.AddConfig("kics", "", "")

		lastscan, err = cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/cx-michael-kubiaczyk/ssba", "master", scanConfigSet.Configurations, map[string]string{})
		if err != nil {
			logger.Fatalf("Failed to run a new scan: %s", err)
		}
		lastscan, err = cx1client.ScanPollingDetailed(&lastscan)
		if err != nil {
			logger.Fatalf("Scan failed with error: %s", err)
		}
		if lastscan.Status != "Completed" {
			logger.Fatalf("Scan did not complete successfully.")
		}
	}

	makeSASTQueries(cx1client, logger, project, lastscan)
	makeIACQueries(cx1client, logger, project, lastscan)

}

// makeSASTQueries runs the full SAST half of the sequence described at the top of
// this file: open an audit session, list existing custom queries, create overrides
// at every level plus a brand-new query, then run one of them and inspect results.
func makeSASTQueries(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project Cx1ClientGo.Project, lastscan Cx1ClientGo.Scan) {
	logger.Infof("Starting Web-Audit session for last successful scan %v", lastscan.String())

	// All query editing/running goes through this session; it's tied to one project+scan.
	session, err := cx1client.GetAuditSessionByID("sast", project.ProjectID, lastscan.ScanID)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	// Always release the session when done, regardless of what happens below.
	defer func() {
		logger.Infof("Terminating audit session %v", session.ID)
		err = cx1client.DeleteAuditSession(&session)
		if err != nil {
			logger.Errorf("Failed to terminate audit session: %s", err)
		}
	}()

	// The base query collection (Cx-provided queries) merged with this session's
	// audit-specific queries (overrides visible only within the session).
	qc, err := cx1client.GetSASTQueryCollection()
	if err != nil {
		logger.Fatalf("Error getting the query collection: %s", err)
	}

	aq, err := cx1client.GetAllAuditSASTQueries(&session)
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)
	cqc := qc.GetCustomQueryCollection()

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Info(q.StringDetailed())
			}
		}
	}

	// Create one override per level (Tenant/"corp", Application, Project) of the same
	// base query, plus a brand-new Tenant-level query below. AuditSessionKeepAlive is
	// called between each because the session can expire during these longer edits;
	// each creation is paired with a deferred delete to leave the tenant clean.
	corpOverride := newSASTCorpOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteSASTQuery(cx1client, logger, &session, corpOverride)

	appOverride := newSASTApplicationOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteSASTQuery(cx1client, logger, &session, appOverride)

	projOverride := newSASTProjectOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteSASTQuery(cx1client, logger, &session, projOverride)

	corpQuery := newSASTCorpQuery(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteSASTQuery(cx1client, logger, &session, corpQuery)

	// Re-fetch the collection so the newly created queries (including their
	// server-assigned QueryIDs) show up in listings.
	logger.Infof("Retrieving an updated list of queries")
	qc, err = cx1client.GetSASTQueryCollection()
	if err != nil {
		logger.Errorf("Error getting the query collection: %s", err)
	}

	aq, err = cx1client.GetAuditSASTQueriesByLevel(&session, cx1client.QueryTypeProject())
	if err != nil {
		logger.Errorf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)

	cqc = qc.GetCustomQueryCollection()
	if corpQuery != nil {
		cqc.UpdateNewQuery(corpQuery) // fill in the missing QueryID for this new query
	}

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Info(q.StringDetailed())
			}
		}
	}

	doQueryEdits(cx1client, logger, &session, projOverride)
}

// doQueryEdits shows the run -> inspect cycle for a SAST query override: first with
// deliberately broken source (to see what a compile failure looks like via
// FailedQueries), then with valid source, walking the Results down to individual
// vulnerabilities.
func doQueryEdits(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, override *Cx1ClientGo.SASTQuery) {
	logger.Infof("Running query with invalid override")
	result, err := cx1client.RunSASTQuery(session, override, "herpaderp")
	if err != nil {
		logger.Errorf("Error running query: %s", err)
	}
	logger.Info("Query errors:")
	for _, r := range result.FailedQueries {
		logger.Infof("Query error: %+v", r)
	}

	// Overwrite the override's source with something valid and re-run it.
	logger.Infof("Running query with valid override - will return all strings results instead")
	result, err = cx1client.RunSASTQuery(session, override, "result = Find_Strings();")
	if err != nil {
		logger.Errorf("Error running query: %s", err)
	}
	logger.Info("Query result:")
	for _, r := range result.Results {
		logger.Infof("Getting vulnerabilities for query result: %+v", r)

		vulnerabilities, err := cx1client.GetQueryRunResultsByID(session, r.RunID)
		if err != nil {
			logger.Errorf("Error getting results: %s", err)
		} else {
			for _, v := range vulnerabilities {
				logger.Infof("Getting details for vulnerability: %+v", v)

				vuln, err := cx1client.GetQueryRunVulnerabilityByID(session, r.RunID, v.VulnerabilityID)
				if err != nil {
					logger.Errorf("Error getting vulnerability: %s", err)
				} else {
					logger.Infof("Details: %+v", vuln)
				}
			}
		}
	}
}

// newSASTCorpOverride creates (or reuses) a Tenant-level ("corp") override of a
// built-in query: find the base query, check whether an override already exists at
// this level, create one if not, then edit its source and severity. The three
// newSAST*Override functions below all follow this same create -> edit source ->
// edit metadata shape, differing only in the override level
// (QueryTypeTenant/Application/Project).
func newSASTCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.SASTQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.SASTQuery {
	logger.Infof("Creating corp override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndID(cx1client.QueryTypeTenant(), session.ProjectID, baseQuery.QueryID)
	var newCorpOverride Cx1ClientGo.SASTQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newCorpOverride = *existingQuery
	} else {
		newCorpOverride, err = cx1client.CreateSASTQueryOverride(session, cx1client.QueryTypeTenant(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newCorpOverride.StringDetailed())
		}
	}

	updatedQuery, _, err := cx1client.UpdateSASTQuerySource(session, newCorpOverride, "result = base.Spring_Missing_Expect_CT_Header(); // corp override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		newCorpOverride = updatedQuery
	}

	metadata := newCorpOverride.GetMetadata()
	metadata.Severity = "Critical"
	updatedQuery, err = cx1client.UpdateSASTQueryMetadata(session, newCorpOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		newCorpOverride = updatedQuery
	}

	if err = qc.UpdateNewQuery(&newCorpOverride); err != nil {
		logger.Errorf("Unable to update query %v from collection: %s", newCorpOverride.String(), err)
	}

	logger.Infof("Created new corp override: %v", newCorpOverride.StringDetailed())
	return &newCorpOverride
}

// newSASTApplicationOverride is the same create -> edit source -> edit metadata
// sequence as newSASTCorpOverride, but at the Application level.
func newSASTApplicationOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.SASTQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.SASTQuery {
	logger.Infof("Creating application-level override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndID(cx1client.QueryTypeApplication(), session.ProjectID, baseQuery.QueryID)
	var newApplicationOverride Cx1ClientGo.SASTQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newApplicationOverride = *existingQuery
	} else {
		newApplicationOverride, err = cx1client.CreateSASTQueryOverride(session, cx1client.QueryTypeApplication(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newApplicationOverride.StringDetailed())
		}
	}

	updatedQuery, _, err := cx1client.UpdateSASTQuerySource(session, newApplicationOverride, "result = base.Spring_Missing_Expect_CT_Header(); // application override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		newApplicationOverride = updatedQuery
	}

	metadata := newApplicationOverride.GetMetadata()
	metadata.Severity = "Medium"
	newApplicationOverride, err = cx1client.UpdateSASTQueryMetadata(session, newApplicationOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	}

	qc.UpdateNewQuery(&newApplicationOverride)

	logger.Infof("Created new application override: %v", newApplicationOverride.StringDetailed())
	return &newApplicationOverride
}

// newSASTProjectOverride is the same create -> edit source -> edit metadata
// sequence as newSASTCorpOverride, but at the Project level.
func newSASTProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.SASTQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.SASTQuery {
	logger.Infof("Creating project override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndID(cx1client.QueryTypeProject(), session.ProjectID, baseQuery.QueryID)
	var newProjectOverride Cx1ClientGo.SASTQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newProjectOverride = *existingQuery
	} else {
		newProjectOverride, err = cx1client.CreateSASTQueryOverride(session, cx1client.QueryTypeProject(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newProjectOverride.StringDetailed())
		}
	}

	newProjectOverride, _, err = cx1client.UpdateSASTQuerySource(session, newProjectOverride, "result = base.Spring_Missing_Expect_CT_Header(); // project override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	}

	metadata := newProjectOverride.GetMetadata()
	metadata.Severity = "High"
	newProjectOverride, err = cx1client.UpdateSASTQueryMetadata(session, newProjectOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	}

	qc.UpdateNewQuery(&newProjectOverride)

	logger.Infof("Created new project override: %v", newProjectOverride.StringDetailed())
	return &newProjectOverride
}

// newSASTCorpQuery creates a brand-new Tenant-level query from scratch (as opposed
// to overriding an existing one, like the newSAST*Override functions above) by
// constructing a full SASTQuery struct and passing it to CreateNewSASTQuery.
func newSASTCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.SASTQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.SASTQuery {
	logger.Infof("Creating corp query under session %v", session.ID)
	tb := true
	NewQuery := Cx1ClientGo.SASTQuery{
		Source:             "result = Find_Strings().FindByName(\"test\"); // new corp query",
		Name:               "Test_String",
		Group:              "Java_Spring",
		Language:           "Java",
		Severity:           "Low",
		CweID:              123,
		IsExecutable:       &tb,
		QueryDescriptionId: 123,
	}

	cx1client.AuditSessionKeepAlive(session)
	newCorpQuery, _, err := cx1client.CreateNewSASTQuery(session, NewQuery)
	if err != nil {
		logger.Errorf("Failed to create new corp query: %s", err)
		return nil
	}

	qc.UpdateNewQuery(&newCorpQuery)

	logger.Infof("Created new corp query: %v", newCorpQuery.StringDetailed())
	logger.Infof(" - Query IDs for brand-new queries are unknown until the full query collection is refreshed via client.GetQueries()")
	return &newCorpQuery
}

// DeleteSASTQuery removes a single override/query by its EditorKey - deferred once
// per created query/override in makeSASTQueries above so the tenant ends up clean.
func DeleteSASTQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, query *Cx1ClientGo.SASTQuery) {
	if query != nil {
		logger.Infof("Deleting custom query: %v", query.StringDetailed())
		err := cx1client.DeleteQueryOverrideByKey(session, query.EditorKey)
		if err != nil {
			logger.Errorf("Failed to delete custom query %v: %s", query.StringDetailed(), err)
		}
	}
}

// makeIACQueries mirrors makeSASTQueries for the IAC/KICS engine: open an audit
// session, list existing custom queries, create overrides at every level plus a
// brand-new query. It does not run a query afterwards - the IAC audit API doesn't
// expose a run/results cycle the way SAST's RunSASTQuery does.
func makeIACQueries(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project Cx1ClientGo.Project, lastscan Cx1ClientGo.Scan) {

	qc, err := cx1client.GetIACQueryCollection()
	if err != nil {
		logger.Fatalf("Error getting the query collection: %s", err)
	}

	logger.Infof("Starting IAC Web-Audit session for last successful scan %v", lastscan.String())

	session, err := cx1client.GetAuditSessionByID("iac", project.ProjectID, lastscan.ScanID)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	defer func() {
		// Wait for user input, like hitting enter, before continuing.
		//logger.Infof("Press 'Enter' to continue...")
		//_, _ = os.Stdin.Read(make([]byte, 1))
		//logger.Infof("Continuing...")

		logger.Infof("Terminating audit session %v", session.ID)
		err = cx1client.DeleteAuditSession(&session)
		if err != nil {
			logger.Errorf("Failed to terminate audit session: %s", err)
		}
	}()

	aq, err := cx1client.GetAuditIACQueriesByLevel(&session, cx1client.QueryTypeProject())
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)
	qc.GetCustomQueryCollection().Print(logger)

	// Same per-level override + brand-new query pattern as the SAST half above.
	corpOverride := newIACCorpOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteIACQuery(cx1client, logger, &session, corpOverride)

	appOverride := newIACApplicationOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteIACQuery(cx1client, logger, &session, appOverride)

	projOverride := newIACProjectOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteIACQuery(cx1client, logger, &session, projOverride)

	corpQuery := newIACCorpQuery(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteIACQuery(cx1client, logger, &session, corpQuery)

	// Re-fetch the collection so the newly created queries show up in listings.
	logger.Infof("Retrieving an updated list of queries")
	qc, err = cx1client.GetIACQueryCollection()
	if err != nil {
		logger.Errorf("Error getting the query collection: %s", err)
	}

	aq, err = cx1client.GetAuditIACQueriesByLevel(&session, cx1client.QueryTypeProject())
	if err != nil {
		logger.Errorf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)

	cx1client.GetIACCollectionAuditMetadata(&session, &qc, true)

	if corpQuery != nil {
		qc.UpdateNewQuery(corpQuery) // fill in the missing QueryID for this new query
	}

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)
	qc.GetCustomQueryCollection().Print(logger)
}

// newIACCorpOverride is the IAC equivalent of newSASTCorpOverride: find the base
// query, check for an existing Tenant-level override (by Key instead of QueryID -
// IAC queries are keyed differently from SAST ones), create one if needed, then edit
// its source and severity. The three newIAC*Override functions below all follow this
// same shape, differing only in the override level.
func newIACCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.IACQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.IACQuery {
	logger.Infof("Creating corp override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Dockerfile", "common", "Apt Get Install Lists Were Not Deleted")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Dockerfile - common - Apt Get Install Lists Were Not Deleted")
		return nil
	} else {
		logger.Infof("Found query: %v", baseQuery.StringDetailed())
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndKey(cx1client.QueryTypeTenant(), cx1client.QueryTypeTenant(), baseQuery.Key)
	var newCorpOverride Cx1ClientGo.IACQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newCorpOverride = *existingQuery
	} else {
		newCorpOverride, err = cx1client.CreateIACQueryOverride(session, cx1client.QueryTypeTenant(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newCorpOverride.StringDetailed())
		}
	}

	newCorpOverride, _, err = cx1client.UpdateIACQuerySource(session, newCorpOverride, iacSrc)
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		logger.Infof("Updated query source: %v", newCorpOverride.StringDetailed())
	}

	metadata := newCorpOverride.GetMetadata()
	metadata.Severity = "Critical"
	newCorpOverride, err = cx1client.UpdateIACQueryMetadata(session, newCorpOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		logger.Infof("Updated query metadata: %v", newCorpOverride.StringDetailed())
	}

	if err = qc.UpdateNewQuery(&newCorpOverride); err != nil {
		logger.Errorf("Unable to update query %v from collection: %s", newCorpOverride.String(), err)
	}

	logger.Infof("Created new corp override: %v", newCorpOverride.StringDetailed())
	return &newCorpOverride
}

// newIACApplicationOverride is the same create -> edit source -> edit metadata
// sequence as newIACCorpOverride, but at the Application level.
func newIACApplicationOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.IACQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.IACQuery {
	logger.Infof("Creating application override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Dockerfile", "common", "Apt Get Install Lists Were Not Deleted")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Dockerfile - common - Apt Get Install Lists Were Not Deleted")
		return nil
	} else {
		logger.Infof("Found query: %v", baseQuery.StringDetailed())
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndKey(cx1client.QueryTypeApplication(), session.ProjectID, baseQuery.Key)
	var newAppOverride Cx1ClientGo.IACQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newAppOverride = *existingQuery
	} else {
		newAppOverride, err = cx1client.CreateIACQueryOverride(session, cx1client.QueryTypeApplication(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newAppOverride.StringDetailed())
		}
	}

	newAppOverride, _, err = cx1client.UpdateIACQuerySource(session, newAppOverride, iacSrc)
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		logger.Infof("Updated query source: %v", newAppOverride.StringDetailed())
	}

	metadata := newAppOverride.GetMetadata()
	metadata.Severity = "Medium"
	newAppOverride, err = cx1client.UpdateIACQueryMetadata(session, newAppOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		logger.Infof("Updated query metadata: %v", newAppOverride.StringDetailed())
	}

	if err = qc.UpdateNewQuery(&newAppOverride); err != nil {
		logger.Errorf("Unable to update query %v from collection: %s", newAppOverride.String(), err)
	}

	logger.Infof("Created new application override: %v", newAppOverride.StringDetailed())
	return &newAppOverride
}

// newIACProjectOverride is the same create -> edit source -> edit metadata sequence
// as newIACCorpOverride, but at the Project level.
func newIACProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.IACQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.IACQuery {
	logger.Infof("Creating project override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Dockerfile", "common", "Apt Get Install Lists Were Not Deleted")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Dockerfile - common - Apt Get Install Lists Were Not Deleted")
		return nil
	} else {
		logger.Infof("Found query: %v", baseQuery.StringDetailed())
	}

	cx1client.AuditSessionKeepAlive(session)
	existingQuery := qc.GetQueryByLevelAndKey(cx1client.QueryTypeProject(), session.ProjectID, baseQuery.Key)
	var newProjectOverride Cx1ClientGo.IACQuery
	var err error
	if existingQuery != nil {
		logger.Infof("Query already exists at this level as %v, skipping create", existingQuery.StringDetailed())
		newProjectOverride = *existingQuery
	} else {
		newProjectOverride, err = cx1client.CreateIACQueryOverride(session, cx1client.QueryTypeProject(), baseQuery)
		if err != nil {
			logger.Errorf("Failed to create override: %s", err)
			return nil
		} else {
			logger.Infof("Created new override: %v", newProjectOverride.StringDetailed())
		}
	}

	newProjectOverride, _, err = cx1client.UpdateIACQuerySource(session, newProjectOverride, iacSrc)
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		logger.Infof("Updated query source: %v", newProjectOverride.StringDetailed())
	}

	metadata := newProjectOverride.GetMetadata()
	metadata.Severity = "Info"
	newProjectOverride, err = cx1client.UpdateIACQueryMetadata(session, newProjectOverride, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		logger.Infof("Updated query metadata: %v", newProjectOverride.StringDetailed())
	}

	if err = qc.UpdateNewQuery(&newProjectOverride); err != nil {
		logger.Errorf("Unable to update query %v from collection: %s", newProjectOverride.String(), err)
	}

	logger.Infof("Created new project override: %v", newProjectOverride.StringDetailed())
	return &newProjectOverride
}

// newIACCorpQuery creates a brand-new Tenant-level query from scratch (as opposed to
// overriding an existing one, like the newIAC*Override functions above) by
// constructing a full IACQuery struct and passing it to CreateNewIACQuery.
func newIACCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.IACQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.IACQuery {
	logger.Infof("Creating corp query under session %v", session.ID)
	NewQuery := Cx1ClientGo.IACQuery{
		Name:           "TestNewQuery",
		Description:    "Test new query",
		DescriptionURL: "http://test.com/newquery",
		Platform:       "Dockerfile",
		Group:          "common",
		Category:       "Supply-Chain",
		Severity:       "High",
		CWE:            "",
		Level:          cx1client.QueryTypeTenant(),
		Custom:         true,
		Source:         iacSrc,
	}

	cx1client.AuditSessionKeepAlive(session)
	newCorpQuery, _, err := cx1client.CreateNewIACQuery(session, NewQuery)
	if err != nil {
		logger.Errorf("Failed to create new corp query: %s", err)
		return nil
	}

	qc.UpdateNewQuery(&newCorpQuery)

	logger.Infof("Created new corp query: %v", newCorpQuery.StringDetailed())
	logger.Infof(" - Query IDs for brand-new queries are unknown until the full query collection is refreshed via client.GetQueries()")
	return &newCorpQuery
}

// DeleteIACQuery removes a single override/query by its QueryID - deferred once per
// created query/override in makeIACQueries above so the tenant ends up clean.
func DeleteIACQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, query *Cx1ClientGo.IACQuery) {
	if query != nil {
		logger.Infof("Deleting custom query: %v", query.StringDetailed())
		err := cx1client.DeleteQueryOverrideByKey(session, query.QueryID)
		if err != nil {
			logger.Errorf("Failed to delete custom query %v: %s", query.StringDetailed(), err)
		}
	}
}
