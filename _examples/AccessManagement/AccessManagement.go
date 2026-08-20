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

	checkCurrentUserAccess(cx1client, logger)
	testclient, serviceuser, err := createOIDCClient(cx1client, logger)
	if err != nil {
		logger.Fatalf("Failed to get or create OIDC Client: %s", err)
	} else {
		_, err = cx1client.GetClientSecret(&testclient)
		if err != nil {
			logger.Errorf("Failed to retrieve secret for new client: %s", err)
		}
	}

	err = addAccessAssignments(cx1client, testclient, serviceuser, logger)

	if err != nil && !strings.Contains(err.Error(), "409") {
		logger.Errorf("Failed to add user assignment for cx1clientgo_test service user: %s", err)
	} else {
		logger.Infof("Testing new OIDC Client by logging in as cx1clientgo_test")
		testcx1client, err := Cx1ClientGo.NewOAuthClient(httpClient, cx1client.GetBaseURL(), cx1client.GetIAMURL(), cx1client.GetTenantName(), testclient.ClientID, testclient.ClientSecret, logger)
		if err != nil {
			logger.Errorf("Failed to log in as 'cx1clientgo_test' OIDC Client: %s", err)
		} else {
			checkCurrentUserAccess(testcx1client, logger)
		}
	}

	err = cx1client.DeleteClientByID(testclient.ID)
	if err != nil {
		logger.Fatalf("Failed to delete oidc client 'cx1clientgo_test': %s", err)
	}

}

func checkCurrentUserAccess(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) {
	logger.Infof("Currently logged in as: %v", cx1client.GetCurrentUsername())

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

	tenantId := cx1client.GetTenantID()
	hasAccess, err := cx1client.CheckAccessToResourceByID(tenantId, "tenant", "ast-scanner")
	if err != nil {
		logger.Errorf("Failed to check current user's access to tenant %v: %s", tenantId, err)
		return
	}

	logger.Infof("Current user has ast-scanner access to tenant %v: %t", tenantId, hasAccess)
}

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

func addAccessAssignments(cx1client *Cx1ClientGo.Cx1Client, client Cx1ClientGo.OIDCClient, user Cx1ClientGo.User, logger *logrus.Logger) error {
	role, err := cx1client.GetRoleByName("ast-scanner")
	if err != nil {
		return err
	}

	_, err = cx1client.CreateAccessAssignment(nil, nil, &client, nil, nil, []Cx1ClientGo.AccessAssignedRole{{Name: role.Name, Id: role.RoleID}})
	if err != nil {
		return fmt.Errorf("failed to assign access: %s", err)
	}

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
