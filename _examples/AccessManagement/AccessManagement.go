// AccessManagement demonstrates the Access Control object model: checking what the
// currently authenticated user/client can access, then provisioning a brand new
// OIDC Client with its own role-based access, and cleaning it up again:
//   - checking the current user/client's access (CheckAccessibleResources,
//     CheckAccessToResourceByID)
//   - creating (or reusing) an OIDC Client + its service account User, and assigning
//     that User a platform Role directly (ast-scanner)
//   - granting the OIDC Client itself a tenant-level Access Assignment, then logging
//     in as that client to confirm it has the same access as the role grants
//   - deleting the OIDC Client at the end
//
// This is also the reference for the two most common authentication constructors:
// NewClient (env/flag-based, used for the initial login) and NewOAuthClient (client
// ID + secret, used below to log in as the newly created service account).
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

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

	logger.Infof("Starting")

	httpClient := &http.Client{}
	cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	// Show what the currently logged-in user/client can access before creating anything.
	checkCurrentUserAccess(cx1client, logger)

	// Get or create a dedicated OIDC Client + service account, granting the service
	// account user the ast-scanner role directly (user-level, not an access assignment).
	testclient, serviceuser, err := createOIDCClient(cx1client, logger)
	if err != nil {
		logger.Fatalf("Failed to get or create OIDC Client: %s", err)
	} else {
		// Client secrets aren't returned by the list/get APIs by default - fetch it explicitly.
		_, err = cx1client.GetClientSecret(&testclient)
		if err != nil {
			logger.Errorf("Failed to retrieve secret for new client: %s", err)
		}
	}

	// Separately, grant the OIDC Client itself (not just its service account user)
	// tenant-level access via an Access Assignment.
	err = addAccessAssignments(cx1client, testclient, serviceuser, logger)

	if err != nil && !strings.Contains(err.Error(), "409") {
		logger.Errorf("Failed to add user assignment for cx1clientgo_test service user: %s", err)
	} else {
		// Log in as the new client (via NewOAuthClient) to confirm it now has the
		// same tenant-level access shown for the original user above.
		logger.Infof("Testing new OIDC Client by logging in as cx1clientgo_test")
		testcx1client, err := Cx1ClientGo.NewOAuthClient(httpClient, cx1client.GetBaseURL(), cx1client.GetIAMURL(), cx1client.GetTenantName(), testclient.ClientID, testclient.ClientSecret, logger)
		if err != nil {
			logger.Errorf("Failed to log in as 'cx1clientgo_test' OIDC Client: %s", err)
		} else {
			checkCurrentUserAccess(testcx1client, logger)
		}
	}

	// Clean up the OIDC Client (and its service account) created above.
	err = cx1client.DeleteClientByID(testclient.ID)
	if err != nil {
		logger.Fatalf("Failed to delete oidc client 'cx1clientgo_test': %s", err)
	}

}

// checkCurrentUserAccess reports the ast-scanner role authorizations of whichever
// user/client is currently logged in - called once for the original user and again
// for the newly created OIDC Client, to show they end up with equivalent access.
func checkCurrentUserAccess(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) {
	logger.Infof("Currently logged in as: %v", cx1client.GetCurrentUsername())

	// List every tenant/project/application the current identity has ast-scanner access to.
	allAccess, accessibleResources, err := cx1client.CheckAccessibleResources([]string{"tenant", "project", "application"}, "ast-scanner")
	if err != nil {
		logger.Errorf("Failed to check current user access assignments: %s", err)
		return
	}

	logger.Infof("Current user has access to all: %t", allAccess)
	logger.Infof("Current user has the following resources accessible: ")
	for _, a := range accessibleResources {
		logger.Infof(" - %v %v: %v", a.ResourceType, a.ResourceID, strings.Join(a.Roles, ","))
	}

	// Also check access to one specific resource (the tenant itself) directly by ID.
	tenantId := cx1client.GetTenantID()
	hasAccess, err := cx1client.CheckAccessToResourceByID(tenantId, "tenant", "ast-scanner")
	if err != nil {
		logger.Errorf("Failed to check current user's access to tenant %v: %s", tenantId, err)
		return
	}

	logger.Infof("Current user has ast-scanner access to tenant %v: %t", tenantId, hasAccess)
}

// createOIDCClient gets or creates an OIDC Client (idempotent, like the various
// GetOrCreate* helpers used elsewhere), then assigns its service account User the
// ast-scanner Role directly - a role grant on the user, distinct from the tenant-level
// Access Assignment made against the client itself in addAccessAssignments below.
func createOIDCClient(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) (Cx1ClientGo.OIDCClient, Cx1ClientGo.User, error) {
	testclient, err := cx1client.GetClientByName("cx1clientgo_test")
	var user Cx1ClientGo.User
	if err != nil {
		logger.Warnf("Failed to find existing OIDC Client 'cx1clientgo_test': %s", err)
		testclient, err = cx1client.CreateClient("cx1clientgo_test", []string{ /*no email for notification*/ }, 30)
		if err != nil {
			return testclient, user, fmt.Errorf("failed to create oidc client 'cx1clientgo_test': %s", err)
		}
		logger.Infof("Created OIDC Client 'cx1clientgo_test'")
	}

	// Every OIDC Client has a backing service account User - fetch it to assign roles.
	user, err = cx1client.GetServiceAccountByID(testclient.ID)
	if err != nil {
		return testclient, user, fmt.Errorf("failed to get service account for oidc client 'cx1clientgo_test': %s", err)
	}

	logger.Infof("cx1clientgo_test oidc client service account user is: %v", user.String())

	scanner_role, err := cx1client.GetRoleByName("ast-scanner")
	if err != nil {
		return testclient, user, fmt.Errorf("failed to find 'ast-scanner' role: %s", err)
	}

	err = cx1client.AddUserRoles(&user, &[]Cx1ClientGo.Role{scanner_role})
	if err != nil {
		return testclient, user, fmt.Errorf("failed to add 'ast-scanner' role to user: %s", err)
	}
	return testclient, user, nil
}

// addAccessAssignments grants the OIDC Client (as opposed to its service account
// User) a tenant-level Access Assignment for the ast-scanner Role, then confirms the
// assignment exists by looking it up from the entity side.
func addAccessAssignments(cx1client *Cx1ClientGo.Cx1Client, client Cx1ClientGo.OIDCClient, user Cx1ClientGo.User, logger *logrus.Logger) error {
	role, err := cx1client.GetRoleByName("ast-scanner")
	if err != nil {
		return err
	}

	// CreateAccessAssignment's nil arguments mean "no user/group being granted access" -
	// here only the OIDC client itself receives the tenant-level role.
	_, err = cx1client.CreateAccessAssignment(nil, nil, &client, nil, nil, []Cx1ClientGo.AccessAssignedRole{{Name: role.Name, Id: role.RoleID}})
	if err != nil {
		return fmt.Errorf("failed to assign access: %s", err)
	}

	// Confirm the assignment took effect by resolving it from the entity (client) side.
	accessAssignment, err := cx1client.GetResourcesAccessibleToEntityByID(user.UserID, "client", []string{"tenant"})
	if err != nil {
		return fmt.Errorf("failed to get entities with access to tenant: %s", err)
	}
	if len(accessAssignment) != 1 {
		return fmt.Errorf("got %d access assignments", len(accessAssignment))
	}
	logger.Infof("Assignment: %v", accessAssignment[0].String())

	return nil
}
