package Cx1ClientGo

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	//"io/ioutil"
	"net/http"
)

var cxOrigin = "Cx1-Client-GoLang"
var scanEngineLicenseMap = map[string]string{
	"sast":       "SAST",
	"sca":        "SCA",
	"kics":       "KICS",
	"iac":        "KICS",
	"containers": "Containers",
	//"?":            "Fusion",
	"apisec": "API Security",
	//"?":            "DAST",
	//"?":            "Malicious Packages",
	//"?":            "Cloud Insights",
	//"?":            "Application Risk Management",
	//"microengines": "Enterprise Secrets", // microengines- "Value": { "2ms" : "true" }
	"secrets": "Enterprise Secrets",
	"2ms":     "Enterprise Secrets",
	//"?":            "AI Protection",
	//"?":            "SCS",
}

// var astAppID string
// var tenantID string
// var tenantOwner *TenantOwner
var cxVersion VersionInfo

//var cx1UserAgent string = "Cx1ClientGo"

// Main entry for users of this client when using OAuth Client ID & Client Secret:
func NewOAuthClient(client *http.Client, base_url, iam_url, tenant, client_id, client_secret string, logger Logger) (*Cx1Client, error) {
	if base_url == "" || iam_url == "" || tenant == "" || client_id == "" || client_secret == "" || logger == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided")
	}

	if l := len(base_url); base_url[l-1:] == "/" {
		base_url = base_url[:l-1]
	}
	if l := len(iam_url); iam_url[l-1:] == "/" {
		iam_url = iam_url[:l-1]
	}

	/*ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	conf := &clientcredentials.Config{
		ClientID:     client_id,
		ClientSecret: client_secret,
		TokenURL:     fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant),
	}

	oauthclient := conf.Client(ctx)

	token, err := conf.Token(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := parseJWT(token.AccessToken)
	if err != nil {
		return nil, err
	}*/

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cli := Cx1Client{
		httpClient: client,
		baseUrl:    base_url,
		iamUrl:     iam_url,
		tenant:     tenant,
		logger:     logger,
		IsUser:     false,
		auth: Cx1ClientAuth{
			ClientID:     client_id,
			ClientSecret: client_secret,
		},
	}

	err := cli.InitializeClient(false)
	return &cli, err
}

// Old entry for users of this client when using API Key
// You can use the new "FromAPIKey" initializer with fewer parameters
func NewAPIKeyClient(client *http.Client, base_url string, iam_url string, tenant string, api_key string, logger Logger) (*Cx1Client, error) {
	return ResumeAPIKeyClient(client, api_key, "", logger)
}

func FromAPIKey(client *http.Client, api_key, last_token string, logger Logger) (*Cx1Client, error) {
	return ResumeAPIKeyClient(client, api_key, last_token, logger)
}

func ResumeAPIKeyClient(client *http.Client, api_key, last_token string, logger Logger) (*Cx1Client, error) {
	if (api_key == "" && last_token == "") || logger == nil || client == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided, requires (API Key or last_token) and logger and client")
	}

	var claims Cx1Claims
	var err error

	if last_token != "" {
		claims, err = parseJWT(last_token)
		if err != nil {
			return nil, err
		}
	} else {
		claims, err = parseJWT(api_key)
		if err != nil {
			return nil, err
		}
	}

	/*
		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

		conf := &oauth2.Config{
			ClientID: "ast-app",
			Endpoint: oauth2.Endpoint{
				TokenURL: fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", claims.IAMURL, claims.TenantName),
			},
		}

		var refreshToken *oauth2.Token

		if last_token != "" {
			claims, err = parseJWT(last_token)
			if err != nil {
				logger.Warningf("Failed parsing last token: %s", err)
			}

			refreshToken = &oauth2.Token{
				AccessToken:  last_token,
				RefreshToken: api_key,
				Expiry:       claims.ExpiryTime.UTC(),
			}
		} else {
			refreshToken = &oauth2.Token{
				AccessToken:  "",
				RefreshToken: api_key,
				Expiry:       time.Now().UTC(),
			}
		}

		token, err := conf.TokenSource(ctx, refreshToken).Token()
		if err != nil {
			err = fmt.Errorf("failed getting a token: %s", err)
			logger.Errorf(err.Error())
			return nil, err
		}

		oauthTransport := &oauth2.Transport{
			Source: conf.TokenSource(ctx, refreshToken),
			Base:   client.Transport,
		}

		oauthclient := &http.Client{
			Transport: oauthTransport,
			Timeout:   client.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		claims, err = parseJWT(token.AccessToken)
		if err != nil {
			return nil, err
		}*/

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cli := Cx1Client{
		httpClient: client,
		logger:     logger,
		IsUser:     true,
		auth: Cx1ClientAuth{
			APIKey:      api_key,
			AccessToken: last_token,
		},
	}
	cli.SetClaims(claims)

	err = cli.InitializeClient(last_token != "")
	return &cli, err
}

func FromToken(client *http.Client, last_token string, logger Logger) (*Cx1Client, error) {
	return ResumeAPIKeyClient(client, "", last_token, logger)
}

// Convenience function that reads command-line flags to create the Cx1Client
func NewClient(client *http.Client, logger Logger) (*Cx1Client, error) {
	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret)")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key)")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key)")
	Cx1URL := flag.String("cx1", "", "Optional: CheckmarxOne platform URL, if not defined in the test config.yaml")
	IAMURL := flag.String("iam", "", "Optional: CheckmarxOne IAM URL, if not defined in the test config.yaml")
	Tenant := flag.String("tenant", "", "Optional: CheckmarxOne tenant, if not defined in the test config.yaml")
	flag.Parse()

	if *APIKey == "" && (*ClientID == "" || *ClientSecret == "") {
		return nil, fmt.Errorf("no credentials provided - need to supply either 'apikey' or 'client' and 'secret' parameters")
	}

	if *Cx1URL == "" || *IAMURL == "" || *Tenant == "" {
		return nil, fmt.Errorf("no server details provided - need to supply 'cx1' and 'iam' URL parameters plus 'tenant'")
	}

	if *APIKey != "" {
		return NewAPIKeyClient(client, *Cx1URL, *IAMURL, *Tenant, *APIKey, logger)
	} else {
		return NewOAuthClient(client, *Cx1URL, *IAMURL, *Tenant, *ClientID, *ClientSecret, logger)
	}
}

func (c Cx1Client) String() string {
	return fmt.Sprintf("%v on %v ", c.tenant, c.baseUrl)
}

func (c *Cx1Client) InitializeClient(quick bool) error {
	c.SetUserAgent("Cx1ClientGo")

	if err := c.refreshAccessToken(); err != nil {
		return err
	}

	if !quick {
		_ = c.GetTenantID()
		_ = c.GetASTAppID()
		_, _ = c.GetTenantOwner()

		if err := c.RefreshFlags(); err != nil {
			c.logger.Warnf("Failed to get tenant flags: %s", err)
		}

		if !c.IsUser {
			oidcclient, err := c.GetClientByName(c.claims.ClientID)
			if err != nil {
				c.logger.Warnf("Insufficient permissions to retrieve details for current OIDC Client %v: %v", c.claims.ClientID, err)
			} else {
				user, err := c.GetServiceAccountByID(oidcclient.ID)
				if err != nil {
					c.logger.Warnf("Insufficient permissions to retrieve details for user behind OIDC Client %v: %v", c.claims.ClientID, err)
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

	if check, _ := c.version.CheckCxOne("3.12.7"); check >= 0 {
		c.logger.Tracef("Version %v > 3.12.7: AUDIT_QUERY_TENANT = Tenant, AUDIT_QUERY_APPLICATION = Application", c.version.CxOne)
		AUDIT_QUERY_TENANT = "Tenant"
		AUDIT_QUERY_APPLICATION = "Application"
	}

	if check, _ := c.version.CheckCxOne("3.30.45"); check >= 0 {
		c.logger.Tracef("Version %v > 3.30.0: ScanSortCreatedDescending = -created_at", c.version.CxOne)
		ScanSortCreatedDescending = "-created_at"
	}

	c.InitializeClientVars()
	c.InitializePaginationSettings()

	return nil
}

func (c *Cx1Client) RefreshFlags() error {
	var flags map[string]bool = make(map[string]bool, 0)

	c.logger.Debugf("Get Cx1 tenant flags")
	var FlagResponse []struct {
		Name   string `json:"name"`
		Status bool   `json:"status"`
		// Payload interface{} `json:"payload"` // ignoring the payload for now
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/flags?filter=%v", c.tenantID), nil, nil)

	if err != nil {
		return err
	}

	err = json.Unmarshal(response, &FlagResponse)
	if err != nil {
		return err
	}

	for _, fr := range FlagResponse {
		flags[fr.Name] = fr.Status
	}

	c.flags = flags

	return nil
}

func (c Cx1Client) GetFlags() map[string]bool {
	return c.flags
}

func (c Cx1Client) GetLicense() ASTLicense {
	return c.claims.Cx1License
}

func (c Cx1Client) GetClaims() Cx1Claims {
	return c.claims
}
func (c *Cx1Client) SetClaims(claims Cx1Claims) {
	c.claims = claims
	if claims.TenantName != "" {
		c.tenant = claims.TenantName
	}
	if claims.IAMURL != "" {
		c.iamUrl = claims.IAMURL
	}
	if claims.ASTBaseURL != "" {
		c.baseUrl = claims.ASTBaseURL
	}
	if claims.TenantID != "" {
		c.tenantID = claims.TenantID
	}
}

func (c Cx1Client) IsEngineAllowed(engine string) (string, bool) {
	var engineName string
	var licenseName string
	for long, license := range scanEngineLicenseMap {
		if strings.EqualFold(license, engine) || strings.EqualFold(long, engine) {
			engineName = long
			licenseName = license
			break
		}
	}
	if engineName == "" {
		return "", false
	}
	c.logger.Tracef("Checking license for %v/%v", engineName, licenseName)

	for _, eng := range c.claims.Cx1License.LicenseData.AllowedEngines {
		if strings.EqualFold(licenseName, eng) {
			return licenseName, true
		}
	}
	return "", false
}

func (c Cx1Client) CheckFlag(flag string) (bool, error) {
	setting, ok := c.flags[flag]
	if !ok {
		return false, fmt.Errorf("no such flag: %v", flag)
	}

	return setting, nil
}

func (c *Cx1Client) GetTenantOwner() (TenantOwner, error) {
	if c.tenantOwner != nil {
		return *c.tenantOwner, nil
	}

	var owner TenantOwner

	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/owner", nil, nil)
	if err != nil {
		return owner, err
	}

	err = json.Unmarshal(response, &owner)
	if err == nil {
		c.tenantOwner = &owner
	}
	return owner, err
}

func (c Cx1Client) GetVersion() (VersionInfo, error) {
	if c.version != nil {
		return *c.version, nil
	}

	var v VersionInfo
	response, err := c.sendRequest(http.MethodGet, "/versions", nil, nil)
	if err != nil {
		return v, err
	}

	err = json.Unmarshal(response, &v)
	if err != nil {
		return v, err
	}

	v.Parse()
	return v, nil
}

func (c *Cx1Client) GetAccessToken() string {
	return c.auth.AccessToken
}

func (c *Cx1Client) GetCurrentUsername() string {
	return c.claims.Username
}

func (c *Cx1Client) SetLogger(logger Logger) {
	c.logger = logger
}

// returns a copy of this client which can be used separately
// they will not share access tokens or other data after the clone.
func (c Cx1Client) Clone() Cx1Client {
	return c
}

func (c *Cx1Client) SetDeprecationWarning(logged bool) {
	c.suppressdepwarn = !logged
}
