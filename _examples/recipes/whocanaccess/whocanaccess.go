// whocanaccess demonstrates resolving *effective* access to a resource:
// direct Access Assignments can name a User, a Group, or an OIDC Client,
// and a Group grant implies access for every member of that group and
// every member of its nested subgroups. This walks that tree down to
// individual users.
//
// A visited-set guards against revisiting the same group twice (a group
// can appear as a subgroup of more than one parent), which would
// otherwise duplicate work or, in a pathological config, recurse forever.
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

	project, err := cx1client.GetProjectByName("example-webapp")
	if err != nil {
		logger.Fatalf("Failed to find project: %s", err)
	}

	users, err := whoCanAccess(cx1client, logger, project.ProjectID, "project")
	if err != nil {
		logger.Fatalf("Failed to resolve access for project %v: %s", project.Name, err)
	}

	logger.Infof("%d user(s) have effective access to project %v:", len(users), project.Name)
	for _, u := range users {
		fmt.Printf(" - %v\n", u)
	}
}

// whoCanAccess returns the deduplicated set of usernames with effective
// access to a resource, resolving group-based grants recursively.
func whoCanAccess(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, resourceID, resourceType string) ([]string, error) {
	assignments, err := cx1client.GetEntitiesAccessToResourceByID(resourceID, resourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to get access assignments: %s", err)
	}

	seenUsers := make(map[string]bool)
	seenGroups := make(map[string]bool)

	for _, a := range assignments {
		switch a.EntityType {
		case "user":
			seenUsers[a.EntityName] = true
		case "group":
			collectGroupMembers(cx1client, logger, a.EntityID, seenGroups, seenUsers)
		case "client":
			// service accounts aren't human users; note them separately
			// rather than folding them into the user list.
			logger.Infof("OIDC client %v also has direct access", a.EntityName)
		}
	}

	users := make([]string, 0, len(seenUsers))
	for name := range seenUsers {
		users = append(users, name)
	}
	return users, nil
}

func collectGroupMembers(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, groupID string, seenGroups, seenUsers map[string]bool) {
	if seenGroups[groupID] {
		return
	}
	seenGroups[groupID] = true

	group, err := cx1client.GetGroupByID(groupID)
	if err != nil {
		logger.Warnf("Failed to resolve group %v: %s", groupID, err)
		return
	}

	members, err := cx1client.GetGroupMembers(&group)
	if err != nil {
		logger.Warnf("Failed to list members of group %v: %s", group.Name, err)
	} else {
		for _, u := range members {
			seenUsers[u.UserName] = true
		}
	}

	children, err := cx1client.GetGroupChildren(&group)
	if err != nil {
		logger.Warnf("Failed to list child groups of %v: %s", group.Name, err)
		return
	}
	for _, child := range children {
		collectGroupMembers(cx1client, logger, child.GroupID, seenGroups, seenUsers)
	}
}
