package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

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

func (c *Cx1Client) GetClientVars() ClientVars {
	return *c.config.Polling
}

func (c *Cx1Client) SetClientVars(clientvars ClientVars) {
	c.config.Polling = &clientvars
}

func (c *Cx1Client) GetDefaultClientVars() ClientVars {
	return c.config.GetDefaultClientVars()
}

// Retrieve the configured "limit" values for paging when retrieving various object types
// Two default settings are available via GetPaginationDefaults(SingleTenant|MultiTenant)
func (c *Cx1Client) GetPaginationSettings() PaginationSettings {
	return *c.config.Pagination
}

func (c *Cx1Client) SetPaginationSettings(pagination PaginationSettings) {
	c.config.Pagination = &pagination
}

func (c *Cx1Client) GetPaginationDefaultsMultiTenant() PaginationSettings {
	return c.config.GetPaginationDefaultsMultiTenant()
}

func (c *Cx1Client) GetPaginationDefaultsSingleTenant() PaginationSettings {
	return c.config.GetPaginationDefaultsSingleTenant()
}

func (f *BaseFilter) Bump() {
	f.Offset += f.Limit
}

func (f *BaseIAMFilter) Bump() {
	f.First += f.Max
}

func (v VersionInfo) String() string {
	return fmt.Sprintf("CxOne %v, SAST %v, IAC %v", v.CxOne, v.SAST, v.IAC)
}

func (v *VersionInfo) Parse() (error, error, error) {
	var errCx1, errIac, errSast error
	v.vCxOne, errCx1 = versionStringToTriad(v.CxOne)
	v.vSAST, errSast = versionStringToTriad(v.SAST)
	v.vIAC, errIac = versionStringToTriad(v.IAC)
	return errCx1, errIac, errSast
}

// version check returns -1 (current cx1 version lower), 0 (equal), 1 (current cx1 version greater)
func (v VersionInfo) CheckCxOne(version string) (int, error) {
	test, err := versionStringToTriad(version)
	if err != nil {
		return 0, err
	}

	return v.vCxOne.Compare(test), nil
}
func (v VersionInfo) CheckKICS(version string) (int, error) {
	return v.CheckIAC(version)
}
func (v VersionInfo) CheckIAC(version string) (int, error) {
	test, err := versionStringToTriad(version)
	if err != nil {
		return 0, err
	}

	return v.vIAC.Compare(test), nil
}
func (v VersionInfo) CheckSAST(version string) (int, error) {
	test, err := versionStringToTriad(version)
	if err != nil {
		return 0, err
	}

	return v.vSAST.Compare(test), nil
}

func versionStringToTriad(version string) (VersionTriad, error) {
	var v VersionTriad
	if version == "" {
		return v, fmt.Errorf("empty version string")
	}
	str := strings.Split(version, ".")
	if len(str) != 3 {
		return v, fmt.Errorf("version string is not in Major.Minor.Patch format")
	}

	ints := make([]uint64, len(str))
	for id, val := range str {
		ints[id], _ = strconv.ParseUint(val, 10, 64)
	}

	v.Major = uint(ints[0])
	v.Minor = uint(ints[1])
	v.Patch = uint(ints[2])

	return v, nil
}

func (v VersionTriad) Compare(test VersionTriad) int {
	if test.Major < v.Major {
		return 1
	} else if test.Major > v.Major {
		return -1
	} else {
		if test.Minor < v.Minor {
			return 1
		} else if test.Minor > v.Minor {
			return -1
		} else {
			if test.Patch < v.Patch {
				return 1
			} else if test.Patch > v.Patch {
				return -1
			} else {
				return 0
			}
		}
	}
}

func (c *Cx1Client) RefreshFlags() error {
	var flags map[string]bool = make(map[string]bool, 0)

	c.config.Logger.Debugf("Get Cx1 tenant flags")
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

func (c *Cx1Client) GetFlags() map[string]bool {
	return c.flags
}

func (c *Cx1Client) GetLicense() ASTLicense {
	return c.claims.Cx1License
}

func (c *Cx1Client) GetClaims() Cx1Claims {
	return c.claims
}

// Check if the license allows a specific engine: SAST, SCA, IAC/KICS, Containers
func (c *Cx1Client) IsEngineAllowed(engine string) (string, bool) {
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
	c.config.Logger.Tracef("Checking license for %v/%v", engineName, licenseName)

	for _, eng := range c.claims.Cx1License.LicenseData.AllowedEngines {
		if strings.EqualFold(licenseName, eng) {
			return licenseName, true
		}
	}
	return "", false
}

// Check if a feature flag is set
func (c *Cx1Client) CheckFlag(flag string) (bool, error) {
	if len(c.flags) == 0 {
		c.config.Logger.Debugf("No flags defined, refreshing")
		err := c.RefreshFlags()
		if err != nil {
			return false, err
		}
	}
	setting, ok := c.flags[flag]
	if !ok {
		return false, fmt.Errorf("no such flag: %v", flag)
	}

	return setting, nil
}

// Check which user is set as the tenant owner
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

// Retrieve the version strings for various system components
func (c *Cx1Client) GetVersion() (VersionInfo, error) {
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
	return c.config.Auth.AccessToken
}

func (c *Cx1Client) GetCurrentUsername() string {
	return c.claims.Username
}

func (c *Cx1Client) SetLogger(logger Logger) {
	c.config.Logger = logger
}

// returns a copy of this client which can be used separately
// they will not share access tokens or other data after the clone.
func (c *Cx1Client) Clone() Cx1Client {
	return *c
}

// If you are heavily using functions that throw deprecation warnings you can mute them here
// Just don't be surprised when they are actually deprecated
func (c *Cx1Client) SetDeprecationWarning(logged bool) {
	c.config.SuppressDepWarn = !logged
}

func (c *Cx1Client) GetTenantID() string {
	if c.tenantID != "" {
		return c.tenantID
	}

	// This shouldn't ever run since the token should contain & initialize the tenantID.
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "", nil, nil)
	if err != nil {
		c.config.Logger.Warnf("Failed to retrieve tenant ID: %s", err)
		return c.tenantID
	}

	var realms struct {
		ID    string `json:"id"`
		Realm string `json:"realm"`
	} // Sometimes this returns an array of one element? Is it possible to return multiple?

	err = json.Unmarshal(response, &realms)
	if err != nil {
		c.config.Logger.Warnf("Failed to parse tenant ID: %s", err)
		c.config.Logger.Tracef("Response was: %v", string(response))
		return c.tenantID
	}

	if realms.Realm == c.config.Tenant {
		c.tenantID = realms.ID
	}
	if c.tenantID == "" {
		c.config.Logger.Warnf("Failed to retrieve tenant ID: no tenant found matching %v", c.config.Tenant)
	}

	return c.tenantID
}

func (c *Cx1Client) GetTenantName() string {
	return c.config.Tenant
}

func (c *Cx1Client) GetBaseURL() string {
	return c.config.BaseUrl
}

func (c *Cx1Client) GetIAMURL() string {
	return c.config.IamUrl
}

func (u Cx1TokenUserInfo) String() string {
	if u.ClientName != "" {
		return fmt.Sprintf("OIDC Client %v", u.ClientName)
	}
	return fmt.Sprintf("User [%v] %v", ShortenGUID(u.UserID), u.UserName)
}

// this is for convenience when initializing structs with *bool members, thanks golang
func boolPtr(b bool) *bool {
	return &b
}
