// scanandtriage demonstrates a common "make sure this project has been
// scanned, then look at what came back" workflow:
//
//  1. Get or create the target project.
//  2. Reuse its most recent completed scan, or trigger a new one from a
//     git repo and wait for it to finish.
//  3. Pull the SAST results and flag the highest-severity finding by
//     attaching a triage comment (a "results predicate").
//
// This is the shape behind any script that needs "current findings for
// project X" without caring whether a fresh scan needs to run first.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	cx1client, err := Cx1ClientGo.NewClient(&http.Client{}, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	const (
		projectName = "example-webapp"
		repoURL     = "https://github.com/example-org/example-repo"
		branch      = "main"
	)

	project, err := cx1client.GetOrCreateProjectByName(projectName)
	if err != nil {
		logger.Fatalf("Failed to get or create project %v: %s", projectName, err)
	}

	scan, err := getOrRunScan(cx1client, logger, &project, repoURL, branch)
	if err != nil {
		logger.Fatalf("Failed to get a completed scan for project %v: %s", projectName, err)
	}

	if err := triageTopFinding(cx1client, logger, &project, &scan); err != nil {
		logger.Errorf("Failed to triage results for scan %v: %s", scan.ScanID, err)
	}
}

// getOrRunScan reuses the project's latest completed scan if one exists,
// otherwise triggers a new scan from the given repo/branch and polls
// until it reaches a terminal status.
func getOrRunScan(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project *Cx1ClientGo.Project, repoURL, branch string) (Cx1ClientGo.Scan, error) {
	filter := Cx1ClientGo.ScanFilter{
		BaseFilter: Cx1ClientGo.BaseFilter{Limit: cx1client.GetPaginationSettings().Scans},
		ProjectID:  project.ProjectID,
		Statuses:   []string{"Completed"},
	}

	existing, err := cx1client.GetLastScansFiltered(filter)
	if err == nil && len(existing) > 0 {
		logger.Infof("Reusing existing completed scan %v for project %v", existing[0].ScanID, project.Name)
		return existing[0], nil
	}

	logger.Infof("No completed scan found for project %v, starting a new one", project.Name)

	configs := Cx1ClientGo.ScanConfigurationSet{}
	configs.AddScanEngine("sast")
	configs.SetKey(Cx1ClientGo.ConfigurationSettings.SAST.PresetName, "All")
	configs.SetKey(Cx1ClientGo.ConfigurationSettings.SAST.Incremental, "false")

	scan, err := cx1client.ScanProjectGitByID(project.ProjectID, repoURL, branch, configs.Configurations, nil)
	if err != nil {
		return scan, fmt.Errorf("failed to start scan: %s", err)
	}

	logger.Infof("Started scan %v, polling until it completes", scan.ScanID)
	return cx1client.ScanPollingDetailed(&scan)
}

// triageTopFinding pulls all SAST results for the scan and, if any exist,
// attaches a review comment to the first one. In a real workflow you'd
// likely rank findings by severity first; this keeps the recipe focused
// on the predicate-creation mechanic itself.
func triageTopFinding(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project *Cx1ClientGo.Project, scan *Cx1ClientGo.Scan) error {
	results, err := cx1client.GetAllScanResultsByID(scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to fetch scan results: %s", err)
	}

	if len(results.SAST) == 0 {
		logger.Infof("No SAST findings to triage for scan %v", scan.ScanID)
		return nil
	}

	finding := results.SAST[0]
	predicate := finding.CreateResultsPredicate(project.ProjectID, scan.ScanID)
	predicate.State = "Confirmed"
	predicate.Comment = "Flagged for review by the scanandtriage recipe."

	if err := cx1client.AddSASTResultsPredicates([]Cx1ClientGo.SASTResultsPredicates{predicate}); err != nil {
		return fmt.Errorf("failed to add results predicate: %s", err)
	}

	logger.Infof("Marked finding %v as %v", finding.SimilarityID, predicate.State)
	return nil
}
