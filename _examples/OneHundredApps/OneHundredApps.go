// OneHundredApps demonstrates bulk, idempotent provisioning of the Group/Application/
// Project hierarchy at scale - useful as a throwaway data-generation script (e.g. for
// load-testing a tenant) rather than as a realistic one-off task:
//   - for each of 100 numbered tuples, get-or-create a Group, an Application, and a
//     Project (all independently, via the no-argument GetOrCreate* helpers)
//   - assign the Project to the Application (AssignProject + UpdateApplication)
//   - assign the Group to the Project (AssignGroup + UpdateProject)
//   - trigger a git-sourced scan against the Project
//
// Unlike the other concept demos, this one does not wait for the triggered scans to
// complete - it fires all 100 and moves on.
package main

import (
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"

	//	"time"

	"fmt"
	"net/http"

	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := log.New()
	logger.SetLevel(log.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	logger.Infof("Starting")

	httpClient := &http.Client{}
	cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)
	if err != nil {
		log.Fatalf("Error creating client: %s", err)
		return
	}

	// no err means that the client is initialized
	logger.Infof("Client initialized: %v", cx1client.String())

	// Old way to configure a scan:
	// var scanConfig Cx1ClientGo.ScanConfiguration
	// scanConfig.ScanType = "sast"
	// scanConfig.Values = map[string]string{"incremental": "false", "presetName": "All"}

	// Scan config is built once and reused for all 100 triggered scans.
	configSet := Cx1ClientGo.ScanConfigurationSet{}
	configSet.SetKey(Cx1ClientGo.ConfigurationSettings.SAST.Incremental, "true")
	configSet.SetKey(Cx1ClientGo.ConfigurationSettings.SAST.PresetName, "All")

	var i uint64
	for i = 1; i <= 100; i++ {
		// Get-or-create each of the three objects independently - none of them are
		// linked to each other yet at this point.
		group, gerr := cx1client.GetOrCreateGroupByName(fmt.Sprintf("Testgroup%d", i))
		if gerr != nil {
			logger.Errorf("Failed to get Testgroup%d", i)
			continue
		}
		app, aerr := cx1client.GetOrCreateApplicationByName(fmt.Sprintf("Testapp%d", i))
		if aerr != nil {
			logger.Errorf("Failed to get Testapp%d", i)
			continue
		}
		project, perr := cx1client.GetOrCreateProjectByName(fmt.Sprintf("Testproject%d", i))
		if perr != nil {
			logger.Errorf("Failed to get Testproject%d: %v", i, perr)
			continue
		}

		// Link the Project under the Application - AssignProject only updates the
		// in-memory struct, UpdateApplication persists it.
		app.AssignProject(&project)
		err = cx1client.UpdateApplication(&app)
		if err != nil {
			logger.Errorf("Failed to Update application: %s", err)
		}

		// Likewise, link the Group to the Project.
		project.AssignGroup(&group)
		err = cx1client.UpdateProject(&project)

		if err != nil {
			logger.Errorf("Failed to Update project: %s", err)
		}

		// Trigger a scan and move on immediately - this example doesn't poll for
		// completion of any of the 100 scans it starts.
		scan, serr := cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/cx-michael-kubiaczyk/ssba/", "master", configSet.Configurations, map[string]string{})
		if serr != nil {
			logger.Errorf("Error starting scan: %s", err)
		} else {
			logger.Infof("Started scan %v", scan.String())
		}
	}

}
