package Cx1ClientGo

import (
	"fmt"
	"net/http"
)

func (c *Cx1ClientConfiguration) ParseToken(token string) error {
	claims, err := parseJWT(token)
	if err != nil {
		return err
	}
	c.ParseClaims(claims)
	return nil
}

func (c *Cx1ClientConfiguration) ParseClaims(claims Cx1Claims) {
	if c.Cx1Url == "" && claims.ASTBaseURL != "" {
		c.Cx1Url = claims.ASTBaseURL
	}
	if c.IAMUrl == "" && claims.IAMURL != "" {
		c.IAMUrl = claims.IAMURL
	}
	if c.Tenant == "" && claims.TenantName != "" {
		c.Tenant = claims.TenantName
	}

	if l := len(c.Cx1Url); l > 0 && c.Cx1Url[l-1:] == "/" {
		c.Cx1Url = c.Cx1Url[:l-1]
	}
	if l := len(c.IAMUrl); l > 0 && c.IAMUrl[l-1:] == "/" {
		c.IAMUrl = c.IAMUrl[:l-1]
	}
}

// Validate that the configuration is valid
func (c *Cx1ClientConfiguration) Validate() error {
	if c.HttpClient == nil {
		return fmt.Errorf("no HTTP client provided")
	}
	if c.Logger == nil {
		return fmt.Errorf("no logger provided")
	}
	if c.HTTPHeaders == nil {
		c.HTTPHeaders = http.Header{}
		c.HTTPHeaders.Set("User-Agent", "Cx1ClientGo")
	}

	if c.Auth.AccessToken != "" {
		if err := c.ParseToken(c.Auth.AccessToken); err != nil {
			return err
		}
	}

	if c.Auth.APIKey != "" {
		if err := c.ParseToken(c.Auth.APIKey); err != nil {
			return err
		}
	} else {
		if c.Auth.ClientID == "" {
			return fmt.Errorf("no client id set")
		}
		if c.Auth.ClientSecret == "" {
			return fmt.Errorf("no client secret set")
		}
	}

	if c.IAMUrl == "" {
		return fmt.Errorf("no iam url set")
	}
	if c.Tenant == "" {
		return fmt.Errorf("no tenant set")
	}

	if c.Polling == nil {
		polling := c.GetDefaultClientVars()
		c.Polling = &polling
	}
	if c.Pagination == nil {
		config := c.GetPaginationDefaultsMultiTenant()
		c.Pagination = &config
	}

	if c.MaxRetries == nil {
		c.MaxRetries = new(int)
		*c.MaxRetries = 3
	}
	if c.RetryDelay == nil {
		c.RetryDelay = new(int)
		*c.RetryDelay = 5
	}

	return nil
}

func (c *Cx1ClientConfiguration) GetDefaultClientVars() ClientVars {
	return ClientVars{
		MigrationPollingMaxSeconds:                300, // 5 min
		MigrationPollingDelaySeconds:              30,
		AuditEnginePollingMaxSeconds:              300,
		AuditEnginePollingDelaySeconds:            30,
		AuditScanPollingMaxSeconds:                600,
		AuditScanPollingDelaySeconds:              30,
		AuditCompilePollingMaxSeconds:             600,
		AuditCompilePollingDelaySeconds:           30,
		AuditLanguagePollingMaxSeconds:            300,
		AuditLanguagePollingDelaySeconds:          30,
		ReportPollingMaxSeconds:                   300,
		ReportPollingDelaySeconds:                 30,
		ExportPollingMaxSeconds:                   300,
		ExportPollingDelaySeconds:                 30,
		ScanPollingMaxSeconds:                     0,
		ScanPollingDelaySeconds:                   30,
		ProjectApplicationLinkPollingMaxSeconds:   300,
		ProjectApplicationLinkPollingDelaySeconds: 15,
	}
}

func (c *Cx1ClientConfiguration) GetPaginationDefaultsSingleTenant() PaginationSettings {
	return PaginationSettings{
		Applications:     500,
		Branches:         100,
		Clients:          100,
		CxLinks:          100,
		Groups:           200,
		GroupMembers:     100,
		Policies:         50,
		PolicyViolations: 50,
		Projects:         500,
		ProjectOverviews: 50,
		Results:          200,
		Scans:            200,
		ScanSchedules:    200,
		SASTAggregate:    10000,
		Users:            200,
	}
}

func (c *Cx1ClientConfiguration) GetPaginationDefaultsMultiTenant() PaginationSettings {
	return PaginationSettings{
		Applications:     50,
		Branches:         100,
		Clients:          20,
		CxLinks:          100,
		Groups:           100,
		GroupMembers:     50,
		Policies:         20,
		PolicyViolations: 20,
		Projects:         50,
		ProjectOverviews: 100,
		Results:          100,
		Scans:            50,
		ScanSchedules:    50,
		SASTAggregate:    10000,
		Users:            100,
	}
}
