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
	logger.SetLevel(logrus.DebugLevel)
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

	project, _, err := cx1client.GetOrCreateProjectInApplicationByName("test-project", "test-application")
	if err != nil {
		logger.Fatalf("Error getting or creating project 'test-project' under application 'test-application': %s", err)
	}

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
		logger.Infof("Running a new scan")

		scanConfigSet := Cx1ClientGo.ScanConfigurationSet{}
		scanConfigSet.AddConfig("sast", "", "")
		scanConfigSet.AddConfig("kics", "", "")

		lastscan, err = cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/michaelkubiaczyk/ssba", "master", scanConfigSet.Configurations, map[string]string{})
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

func makeSASTQueries(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project Cx1ClientGo.Project, lastscan Cx1ClientGo.Scan) {
	logger.Infof("Starting Web-Audit session for last successful scan %v", lastscan.String())

	session, err := cx1client.GetAuditSessionByID("sast", project.ProjectID, lastscan.ScanID)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	defer func() {
		logger.Infof("Terminating audit session %v", session.ID)
		err = cx1client.DeleteAuditSession(&session)
		if err != nil {
			logger.Errorf("Failed to terminate audit session: %s", err)
		}
	}()

	qc, err := cx1client.GetSASTQueryCollection()
	if err != nil {
		logger.Fatalf("Error getting the query collection: %s", err)
	}

	aq, err := cx1client.GetAuditSASTQueriesByLevelID(&session, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)
	cqc := qc.GetCustomQueryCollection()

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Infof(q.StringDetailed())
			}
		}
	}

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

	logger.Infof("Retrieving an updated list of queries")
	qc, err = cx1client.GetSASTQueryCollection()
	if err != nil {
		logger.Errorf("Error getting the query collection: %s", err)
	}

	aq, err = cx1client.GetAuditSASTQueriesByLevelID(&session, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Errorf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)
	if corpQuery != nil {
		qc.UpdateNewQuery(corpQuery) // fill in the missing QueryID for this new query
	}

	cqc = qc.GetCustomQueryCollection()

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Infof(q.StringDetailed())
			}
		}
	}
}

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

func newSASTCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.SASTQueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.SASTQuery {
	logger.Infof("Creating corp query under session %v", session.ID)
	NewQuery := Cx1ClientGo.SASTQuery{
		Source:             "result = Find_Strings().FindByName(\"test\"); // new corp query",
		Name:               "Test_String",
		Group:              "Java_Spring",
		Language:           "Java",
		Severity:           "Low",
		CweID:              123,
		IsExecutable:       true,
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

func DeleteSASTQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, query *Cx1ClientGo.SASTQuery) {
	if query != nil {
		logger.Infof("Deleting custom query: %v", query.StringDetailed())
		err := cx1client.DeleteQueryOverrideByKey(session, query.EditorKey)
		if err != nil {
			logger.Errorf("Failed to delete custom query %v: %s", query.StringDetailed(), err)
		}
	}
}

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

	aq, err := cx1client.GetAuditIACQueriesByLevelID(&session, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddCollection(&aq)

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)
	qc.GetCustomQueryCollection().Print(logger)

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

	logger.Infof("Retrieving an updated list of queries")
	qc, err = cx1client.GetIACQueryCollection()
	if err != nil {
		logger.Errorf("Error getting the query collection: %s", err)
	}

	aq, err = cx1client.GetAuditIACQueriesByLevelID(&session, cx1client.QueryTypeProject(), project.ProjectID)
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

func DeleteIACQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, query *Cx1ClientGo.IACQuery) {
	if query != nil {
		logger.Infof("Deleting custom query: %v", query.StringDetailed())
		err := cx1client.DeleteQueryOverrideByKey(session, query.QueryID)
		if err != nil {
			logger.Errorf("Failed to delete custom query %v: %s", query.StringDetailed(), err)
		}
	}
}
