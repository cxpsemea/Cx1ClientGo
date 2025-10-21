package Cx1ClientGo

import (
	"fmt"
	"strconv"
	"strings"
)

// miscellaneous functions (ClientVars & Pagination)

func (c Cx1Client) GetClientVars() ClientVars {
	return c.consts
}

func (c *Cx1Client) SetClientVars(clientvars ClientVars) {
	c.consts = clientvars
}

func (c *Cx1Client) InitializeClientVars() {
	c.consts = ClientVars{
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

func (c Cx1Client) GetPaginationSettings() PaginationSettings {
	c.logger.Debugf("Retrieving client vars - polling limits set in seconds")
	return c.pagination
}

func (c *Cx1Client) SetPaginationSettings(pagination PaginationSettings) {
	c.pagination = pagination
}

func (c *Cx1Client) InitializePaginationSettings() {
	c.SetPaginationSettings(c.GetPaginationDefaultsMultiTenant())
}

func (c *Cx1Client) GetPaginationDefaultsSingleTenant() PaginationSettings {
	return PaginationSettings{
		Applications:     500,
		Branches:         100,
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

func (c *Cx1Client) GetPaginationDefaultsMultiTenant() PaginationSettings {
	return PaginationSettings{
		Applications:     50,
		Branches:         100,
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

// this is for convenience when initializing structs with *bool members, thanks golang
func boolPtr(b bool) *bool {
	return &b
}
