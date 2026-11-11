package Cx1ClientGo

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Reads command-line flags to create a Cx1Client
// Useful when writing stand-alone CLI tools
//
// Credentials and endpoints can also be supplied through environment variables, the same ones the
// Checkmarx One CLI (AST CLI) reads. A value given on the command line takes precedence.
// Prefer these over flags for secrets, as command-line arguments are visible to other processes
// (ps, /proc/<pid>/cmdline) and in CI logs:
//
//	-apikey -> CX_APIKEY    -client -> CX_CLIENT_ID    -secret -> CX_CLIENT_SECRET
//	-cx1 -> CX_BASE_URI     -iam -> CX_BASE_AUTH_URI   -tenant -> CX_TENANT
func NewClient(client *http.Client, logger Logger) (*Cx1Client, error) {
	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret). Can also be set with the CX_APIKEY environment variable")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key). Can also be set with the CX_CLIENT_ID environment variable")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key). Can also be set with the CX_CLIENT_SECRET environment variable")
	Cx1URL := flag.String("cx1", "", "Optional: CheckmarxOne platform URL, if not defined in the test config.yaml. Can also be set with the CX_BASE_URI environment variable")
	IAMURL := flag.String("iam", "", "Optional: CheckmarxOne IAM URL, if not defined in the test config.yaml. Can also be set with the CX_BASE_AUTH_URI environment variable")
	Tenant := flag.String("tenant", "", "Optional: CheckmarxOne tenant, if not defined in the test config.yaml. Can also be set with the CX_TENANT environment variable")
	Token := flag.String("token", "", "Optional: A valid access_token. If this value is provided, others will be ignored - the client will lose access when the token expires")
	UserAgent := flag.String("useragent", "Cx1ClientGo", "Optional: A custom user-agent string for all requests to Cx1")
	flag.Parse()

	config := Cx1ClientConfiguration{
		HttpClient:  client,
		Logger:      logger,
		HTTPHeaders: http.Header{},
		Auth: Cx1ClientAuth{
			APIKey:       valueOrEnv(*APIKey, "CX_APIKEY"),
			ClientID:     valueOrEnv(*ClientID, "CX_CLIENT_ID"),
			ClientSecret: valueOrEnv(*ClientSecret, "CX_CLIENT_SECRET"),
			AccessToken:  *Token,
		},
		Cx1Url: valueOrEnv(*Cx1URL, "CX_BASE_URI"),
		IAMUrl: valueOrEnv(*IAMURL, "CX_BASE_AUTH_URI"),
		Tenant: valueOrEnv(*Tenant, "CX_TENANT"),
	}

	config.HTTPHeaders.Add("User-Agent", *UserAgent)

	return NewClientWithOptions(config)
}

// valueOrEnv returns the flag value if it was provided, otherwise the (trimmed) value of the environment variable.
func valueOrEnv(value, envName string) string {
	if value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(envName))
}

// Create a new Cx1Client using OAuth Client ID & Client Secret
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewOAuthClient(client *http.Client, base_url, iam_url, tenant, client_id, client_secret string, logger Logger) (*Cx1Client, error) {
	return NewOAuthClientWithToken(client, base_url, iam_url, tenant, client_id, client_secret, "", logger)
}

// Create a new Cx1Client using OAuth Client ID & Client Secret along with an existing access_token
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewOAuthClientWithToken(client *http.Client, base_url, iam_url, tenant, client_id, client_secret, last_access_token string, logger Logger) (*Cx1Client, error) {
	return NewClientWithOptions(Cx1ClientConfiguration{
		HttpClient: client,
		Logger:     logger,
		Auth: Cx1ClientAuth{
			ClientID:     client_id,
			ClientSecret: client_secret,
			AccessToken:  last_access_token,
		},
		Cx1Url: base_url,
		IAMUrl: iam_url,
		Tenant: tenant,
	})
}

// Create a new Cx1Client using an API Key
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewAPIKeyClient(client *http.Client, api_key string, logger Logger) (*Cx1Client, error) {
	return NewAPIKeyClientWithToken(client, api_key, "", logger)
}

// Create a new Cx1Client using an API Key along with an existing access_token
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewAPIKeyClientWithToken(client *http.Client, api_key, last_access_token string, logger Logger) (*Cx1Client, error) {
	return NewClientWithOptions(Cx1ClientConfiguration{
		HttpClient: client,
		Logger:     logger,
		Auth: Cx1ClientAuth{
			APIKey:      api_key,
			AccessToken: last_access_token,
		},
	})
}

// Create a client from an access token
// The client will be unable to generate a new access token - useful for zero trust workflows
func NewTokenClient(client *http.Client, last_token string, logger Logger) (*Cx1Client, error) {
	return NewClientWithOptions(Cx1ClientConfiguration{
		HttpClient: client,
		Logger:     logger,
		Auth: Cx1ClientAuth{
			AccessToken: last_token,
		},
	})
}

// This function creates a new Cx1Client with the provided configuration.
// This allows for more advanced configuration of a client and is also used by other constructors.
// Most users should use NewClient or NewOAuthClient/NewAPIKeyClient instead for convenience.
func NewClientWithOptions(options Cx1ClientConfiguration) (*Cx1Client, error) {
	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("unable to create client: %v", err)
	}

	options.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cli := Cx1Client{config: options}
	err := cli.InitializeClient(options.QuickStart)
	return &cli, err
}

func (c *Cx1Client) InitializeClient(quick bool) error {
	if err := c.refreshAccessToken(); err != nil {
		return err
	}

	c.parseToken()

	if !quick {
		_ = c.GetTenantID()
		_ = c.GetASTAppID()
		_, _ = c.GetTenantOwner()

		if err := c.RefreshFlags(); err != nil {
			c.config.Logger.Warnf("Failed to get tenant flags: %s", err)
		}

		if !c.IsUser() {
			oidcclient, err := c.GetClientByName(c.Userinfo.ClientName)
			if err != nil {
				c.config.Logger.Warnf("Insufficient permissions to retrieve details for current OIDC Client %v: %v", c.Userinfo.ClientName, err)
			} else {
				user, err := c.GetServiceAccountByID(oidcclient.ID)
				if err != nil {
					c.config.Logger.Warnf("Insufficient permissions to retrieve details for user behind OIDC Client %v: %v", c.Userinfo.ClientName, err)
				} else {
					c.user = &user
				}
			}
		} else {
			_, _ = c.GetCurrentUser()
		}
	}

	var err error
	cxVersion, err = c.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to retrieve cx1 version: %s", err)
	}
	c.version = &cxVersion

	if check, _ := c.version.CheckCxOne("3.12.7"); check < 0 { // old version before 3.12.7
		c.config.Logger.Tracef("Version %v < 3.12.7: AUDIT_QUERY.TENANT = Corp, AUDIT_QUERY.APPLICATION = Team", c.version.CxOne)
		AUDIT_QUERY.TENANT = "Corp"
		AUDIT_QUERY.APPLICATION = "Team"
	}

	if check, _ := c.version.CheckCxOne("3.30.45"); check < 0 { // old version before 3.30.45
		c.config.Logger.Tracef("Version %v < 3.30.0: ScanSortCreatedDescending = +created_at", c.version.CxOne)
		ScanSortCreatedDescending = "+created_at"
	}

	if check, _ := c.version.CheckCxOne("3.62.0"); check >= 0 { // new version 3.62+
		c.config.Logger.Tracef("Version %v >= 3.62.0: audit_query_v310.TENANT = Corp, audit_query_v310.APPLICATION = Application", c.version.CxOne)
		audit_query_v310.APPLICATION = "Application"
		audit_query_v310.TENANT = "Tenant"
	}

	return nil
}

func (c Cx1Client) String() string {
	return fmt.Sprintf("%v @ tenant %v on %v", c.Userinfo.String(), c.config.Tenant, c.config.Cx1Url)
}
