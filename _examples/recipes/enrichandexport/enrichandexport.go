// enrichandexport demonstrates the most common shape found across
// reporting scripts: bulk-fetch a primary list of resources, resolve one
// or more related sub-resources per item, and emit a flat report.
//
// The key trick is the in-memory cache keyed by the related resource's
// ID: many projects share the same SCM repository or application, so
// caching avoids re-fetching a repository or application record once
// it's already been resolved.
//
// Variant worth knowing about: the same list -> resolve -> compare shape
// also underlies read-only reconciliation/audit checks (e.g. "does this
// preset still include query X", "does this project's application
// assignment still match an external record") - swap the CSV-writing
// step for a mismatch check and you get a drift report instead of an
// export, without changing the fetch/cache mechanics below.
package main

import (
	"encoding/csv"
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

	projects, err := cx1client.GetAllProjects()
	if err != nil {
		logger.Fatalf("Failed to list projects: %s", err)
	}

	out, err := os.Create("project-report.csv")
	if err != nil {
		logger.Fatalf("Failed to create output file: %s", err)
	}
	defer out.Close()

	writer := csv.NewWriter(out)
	defer writer.Flush()
	writer.Write([]string{"project", "repository", "application"})

	// Caches avoid re-resolving the same repository or application record
	// once several projects have already pointed us at it.
	repoCache := make(map[uint64]Cx1ClientGo.SCMRepository)
	appCache := make(map[string]Cx1ClientGo.Application)

	for _, project := range projects {
		repoURL := ""
		if project.RepoID != 0 {
			repo, ok := repoCache[project.RepoID]
			if !ok {
				var err error
				repo, err = cx1client.GetSCMRepository(project.RepoID)
				if err != nil {
					logger.Warnf("Failed to resolve repository for project %v: %s", project.Name, err)
				}
				repoCache[project.RepoID] = repo
			}
			repoURL = repo.URL
		}

		appName := ""
		if project.Applications != nil && len(*project.Applications) > 0 {
			appID := (*project.Applications)[0]
			app, ok := appCache[appID]
			if !ok {
				var err error
				app, err = cx1client.GetApplicationByID(appID)
				if err != nil {
					logger.Warnf("Failed to resolve application for project %v: %s", project.Name, err)
				}
				appCache[appID] = app
			}
			appName = app.Name
		}

		writer.Write([]string{project.Name, repoURL, appName})
	}

	logger.Infof("Wrote report for %d projects to project-report.csv", len(projects))
}
