package Cx1ClientGo

import (
	"flag"
	"fmt"
	"net/http"
)

// Reads command-line flags to create a Cx1Client
// Useful when writing stand-alone CLI tools
func NewClient(client *http.Client, logger Logger) (*Cx1Client, error) {
	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret)")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key)")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key)")
	Cx1URL := flag.String("cx1", "", "Optional: CheckmarxOne platform URL, if not defined in the test config.yaml")
	IAMURL := flag.String("iam", "", "Optional: CheckmarxOne IAM URL, if not defined in the test config.yaml")
	Tenant := flag.String("tenant", "", "Optional: CheckmarxOne tenant, if not defined in the test config.yaml")
	Token := flag.String("token", "", "Optional: A valid access_token. If this value is provided, others will be ignored - the client will lose access when the token expires")
	UserAgent := flag.String("useragent", "Cx1ClientGo", "Optional: A custom user-agent string for all requests to Cx1")
	flag.Parse()

	config := Cx1ClientConfiguration{
		HttpClient:  client,
		Logger:      logger,
		HTTPHeaders: http.Header{},
		Auth: Cx1ClientAuth{
			APIKey:       *APIKey,
			ClientID:     *ClientID,
			ClientSecret: *ClientSecret,
			AccessToken:  *Token,
		},
		Cx1Url: *Cx1URL,
		IAMUrl: *IAMURL,
		Tenant: *Tenant,
	}

	config.HTTPHeaders.Add("User-Agent", *UserAgent)

	return NewClientWithOptions(config)
}

// Create a new Cx1Client using OAuth Client ID & Client Secret with an optional access_token to reuse
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewOAuthClient(client *http.Client, base_url, iam_url, tenant, client_id, client_secret, last_token string, logger Logger) (*Cx1Client, error) {
	return NewClientWithOptions(Cx1ClientConfiguration{
		HttpClient: client,
		Logger:     logger,
		Auth: Cx1ClientAuth{
			ClientID:     client_id,
			ClientSecret: client_secret,
			AccessToken:  last_token,
		},
		Cx1Url: base_url,
		IAMUrl: iam_url,
		Tenant: tenant,
	})
}

// Create a new Cx1Client using an API Key with an optional access_token to reuse
// You can also use NewClient instead which automatically pulls from command-line arguments
func NewAPIKeyClient(client *http.Client, api_key, last_token string, logger Logger) (*Cx1Client, error) {
	return NewClientWithOptions(Cx1ClientConfiguration{
		HttpClient: client,
		Logger:     logger,
		Auth: Cx1ClientAuth{
			APIKey:      api_key,
			AccessToken: last_token,
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
	err := cli.InitializeClient(false)
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

		if !c.IsUser {
			oidcclient, err := c.GetClientByName(c.userinfo.ClientName)
			if err != nil {
				c.config.Logger.Warnf("Insufficient permissions to retrieve details for current OIDC Client %v: %v", c.userinfo.ClientName, err)
			} else {
				user, err := c.GetServiceAccountByID(oidcclient.ID)
				if err != nil {
					c.config.Logger.Warnf("Insufficient permissions to retrieve details for user behind OIDC Client %v: %v", c.userinfo.ClientName, err)
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

	if check, _ := c.version.CheckCxOne("3.12.7"); check < 0 {
		c.config.Logger.Tracef("Version %v < 3.12.7: AUDIT_QUERY.TENANT = Corp, AUDIT_QUERY.APPLICATION = Team", c.version.CxOne)
		AUDIT_QUERY.TENANT = "Corp"
		AUDIT_QUERY.APPLICATION = "Team"
	}

	if check, _ := c.version.CheckCxOne("3.30.45"); check < 0 {
		c.config.Logger.Tracef("Version %v < 3.30.0: ScanSortCreatedDescending = +created_at", c.version.CxOne)
		ScanSortCreatedDescending = "+created_at"
	}

	return nil
}

func (c Cx1Client) String() string {
	return fmt.Sprintf("%v @ %v on %v", c.userinfo.String(), c.config.Tenant, c.config.Cx1Url)
}
