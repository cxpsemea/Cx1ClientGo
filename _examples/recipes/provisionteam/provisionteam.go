// provisionteam demonstrates two paired, realistic operational tasks:
//
//   - Onboarding: idempotently build a small object hierarchy for a new
//     team (an Application, a Group, and Owner/Scanner child groups with
//     role bindings and an access grant on the Application). Every step
//     is get-or-create / conflict-tolerant, so running this twice for the
//     same team name is a no-op rather than an error.
//   - Offboarding: concurrently tear down a batch of projects that were
//     provisioned under that application, then remove the application
//     itself.
//
// See _examples/OBJECT_MODEL.md for why Application/Group/Role/Access
// Assignment need to exist in this order.
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

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

	const teamName = "example-team"

	app, err := provisionTeam(cx1client, logger, teamName)
	if err != nil {
		logger.Fatalf("Failed to provision team %v: %s", teamName, err)
	}

	// ... projects would be created under app.ApplicationID here, scanned,
	// used, etc. When the team is decommissioned:
	if err := decommissionTeam(cx1client, logger, &app); err != nil {
		logger.Fatalf("Failed to decommission team %v: %s", teamName, err)
	}
}

// provisionTeam builds the Application -> Group -> child Groups -> Role
// bindings -> Access Assignment hierarchy for a team, tolerating "already
// exists" (409) responses at each step so the workflow can be re-run
// safely (e.g. from a CI job that runs on every commit to a config repo).
func provisionTeam(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, teamName string) (Cx1ClientGo.Application, error) {
	app, err := cx1client.GetOrCreateApplicationByName(teamName)
	if err != nil {
		return app, fmt.Errorf("failed to get or create application: %s", err)
	}

	teamGroup, err := cx1client.GetOrCreateGroupByName(fmt.Sprintf("%v-team", teamName))
	if err != nil {
		return app, fmt.Errorf("failed to get or create group: %s", err)
	}

	role, err := cx1client.GetRoleByName("ast-scanner")
	if err != nil {
		return app, fmt.Errorf("failed to find 'ast-scanner' role: %s", err)
	}

	for _, sub := range []string{"Owners", "Scanners"} {
		subgroup, err := getOrCreateChildGroup(cx1client, logger, &teamGroup, sub)
		if err != nil {
			return app, fmt.Errorf("failed to get or create %v subgroup: %s", sub, err)
		}

		if err := cx1client.AddRolesToGroup(&subgroup, map[string][]string{"ast-app": {role.Name}}); err != nil {
			return app, fmt.Errorf("failed to bind role to %v subgroup: %s", sub, err)
		}

		_, err = cx1client.CreateAccessAssignment(nil, &subgroup, nil, nil, &app,
			[]Cx1ClientGo.AccessAssignedRole{{Id: role.RoleID, Name: role.Name}})
		if err != nil && !strings.Contains(err.Error(), "409") {
			return app, fmt.Errorf("failed to grant %v access on application: %s", sub, err)
		}
		logger.Infof("%v subgroup has access to application %v", sub, app.Name)
	}

	return app, nil
}

func getOrCreateChildGroup(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, parent *Cx1ClientGo.Group, name string) (Cx1ClientGo.Group, error) {
	existing, err := cx1client.GetGroupByPath(fmt.Sprintf("%v/%v", parent.Path, name))
	if err == nil {
		return existing, nil
	}

	logger.Infof("Creating child group %v under %v", name, parent.Name)
	return cx1client.CreateChildGroup(parent, name)
}

// decommissionTeam deletes every project under the application concurrently
// (each deletion is independent), then removes the application itself once
// no projects reference it any more.
func decommissionTeam(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, app *Cx1ClientGo.Application) error {
	if app.ProjectIds == nil || len(*app.ProjectIds) == 0 {
		logger.Infof("No projects to remove under application %v", app.Name)
		return cx1client.DeleteApplication(app)
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(*app.ProjectIds))

	for _, projectID := range *app.ProjectIds {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			project, err := cx1client.GetProjectByID(id)
			if err != nil {
				errs <- fmt.Errorf("failed to look up project %v: %s", id, err)
				return
			}
			if err := cx1client.DeleteProject(&project); err != nil {
				errs <- fmt.Errorf("failed to delete project %v: %s", project.Name, err)
			}
		}(projectID)
	}

	wg.Wait()
	close(errs)

	var failed int
	for err := range errs {
		logger.Errorf("%s", err)
		failed++
	}
	if failed > 0 {
		return fmt.Errorf("failed to delete %d project(s), leaving application in place", failed)
	}

	return cx1client.DeleteApplication(app)
}
