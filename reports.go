package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Reports
// Added the 'sections' variable, originally: "ScanSummary", "ExecutiveSummary", "ScanResults",
func (c *Cx1Client) RequestNewReportByID(scanID, projectID, branch, reportType string, engines, sections []string) (string, error) {
	jsonData := map[string]interface{}{
		"fileFormat": reportType,
		"reportType": "ui",
		"reportName": "scan-report",
		"data": map[string]interface{}{
			"scanId":     scanID,
			"projectId":  projectID,
			"branchName": branch,
			"sections":   sections,
			"scanners":   engines,
			"host":       "",
		},
	}

	jsonBody, err := json.Marshal(jsonData)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/reports", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger report generation for scan %v: %s", scanID, err)
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal([]byte(data), &reportResponse)

	return reportResponse.ReportId, err
}

// the v2 report is the "improved scan report" which can be used the same as the existing RequestNewReportByID
// returns the report ID which can be passed to GetReportStatusByID or ReportPollingByID
// supports pdf, csv, and json format (not xml)
func (c *Cx1Client) RequestNewReportByIDv2(scanID string, scanners []string, format string) (string, error) {
	c.depwarn("RequestNewReportByIDv2", "RequestNewReportByScanIDv2")
	return c.RequestNewReportByScanIDv2(scanID, scanners, []string{}, []string{}, format)
}

func (c *Cx1Client) RequestNewReportByScanIDv2(scanID string, scanners, emails, tags []string, format string) (string, error) {
	severities := []string{"high", "medium"}
	if flag, _ := c.CheckFlag("CVSS_V3_ENABLED"); flag {
		severities = append(severities, "critical")
	}
	return c.RequestNewReportByIDsv2(
		"scan",
		[]string{scanID},
		[]string{"scan-information", "results-overview", "scan-results", "categories", "resolved-results", "vulnerability-details"},
		scanners,
		severities,
		[]string{"to-verify", "confirmed", "urgent"},
		[]string{"new", "recurrent"},
		emails,
		tags,
		format)
}

func (c *Cx1Client) RequestNewReportByProjectIDv2(projectIDs, scanners, emails, tags []string, format string) (string, error) {
	severities := []string{"high", "medium"}
	if flag, _ := c.CheckFlag("CVSS_V3_ENABLED"); flag {
		severities = append(severities, "critical")
	}
	return c.RequestNewReportByIDsv2(
		"project",
		projectIDs,
		[]string{"projects-overview", "total-vulnerabilities-overview", "vulnerabilities-insights"},
		scanners,
		severities,
		[]string{"to-verify", "confirmed", "urgent"},
		[]string{"new", "recurrent"},
		emails,
		tags,
		format)
}

// function used by RequestNewReportByIDv2
func (c *Cx1Client) RequestNewReportByIDsv2(entityType string, ids, sections, scanners, severities, states, statuses, emails, tags []string, format string) (string, error) {
	jsonData := map[string]interface{}{
		"reportName": fmt.Sprintf("improved-%v-report", entityType),
		"sections":   sections,
		"entities": []map[string]interface{}{
			{
				"entity": entityType,
				"ids":    ids,
				"tags":   tags,
			},
		},
		"filters": map[string][]string{
			"scanners":   scanners,
			"severities": severities,
			"states":     states,
			"status":     statuses,
		},
		"reportType": "ui",
		"fileFormat": format,
		"emails":     emails,
	}

	jsonValue, _ := json.Marshal(jsonData)

	data, err := c.sendRequest(http.MethodPost, "/reports/v2", bytes.NewReader(jsonValue), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger report v2 generation for %v(s) %v: %s", entityType, strings.Join(ids, ","), err)
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal(data, &reportResponse)
	return reportResponse.ReportId, err
}

func (c *Cx1Client) GetReportStatusByID(reportID string) (ReportStatus, error) {
	var response ReportStatus

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/%v?returnUrl=true", reportID), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch report status for reportID %v: %s", reportID, err)
		return response, fmt.Errorf("failed to fetch report status for reportID %v: %s", reportID, err)
	}

	err = json.Unmarshal([]byte(data), &response)
	return response, err
}

func (c *Cx1Client) DownloadReport(reportUrl string) ([]byte, error) {
	data, err := c.sendRequestInternal(http.MethodGet, reportUrl, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to download report from url %v: %s", reportUrl, err)
	}
	return data, nil
}

// convenience function, polls and returns the URL to download the report
func (c *Cx1Client) ReportPollingByID(reportID string) (string, error) {
	return c.ReportPollingByIDWithTimeout(reportID, c.consts.ReportPollingDelaySeconds, c.consts.ReportPollingMaxSeconds)
}

func (c *Cx1Client) ReportPollingByIDWithTimeout(reportID string, delaySeconds, maxSeconds int) (string, error) {
	pollingCounter := 0
	for {
		status, err := c.GetReportStatusByID(reportID)
		if err != nil {
			return "", err
		}

		if status.Status == "completed" {
			return status.ReportURL, nil
		} else if status.Status == "failed" {
			return "", fmt.Errorf("report generation failed")
		}

		if maxSeconds != 0 && pollingCounter > maxSeconds {
			return "", fmt.Errorf("report %v polling reached %d seconds, aborting - use cx1client.get/setclientvars to change", ShortenGUID(reportID), pollingCounter)
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}

// SCA-specific Export for SBOM
// formats: CycloneDxjson, CycloneDxxml, Spdxjson
func (c *Cx1Client) RequestNewExportByID(scanId, format string, hidePrivatePackages, hideDevAndTestDependencies, showOnlyEffectiveLicenses bool) (string, error) {
	jsonData := map[string]interface{}{
		"ScanId":     scanId,
		"FileFormat": format,
		"ExportParameters": map[string]interface{}{
			"hidePrivatePackages":        hidePrivatePackages,
			"hideDevAndTestDependencies": hideDevAndTestDependencies,
			"showOnlyEffectiveLicenses":  showOnlyEffectiveLicenses,
		},
	}

	jsonValue, _ := json.Marshal(jsonData)

	data, err := c.sendRequest(http.MethodPost, "/sca/export/requests", bytes.NewReader(jsonValue), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger %v export generation for scan %v: %s", format, scanId, err)
	}

	var exportResponse struct {
		ExportId string
	}
	err = json.Unmarshal(data, &exportResponse)
	return exportResponse.ExportId, err
}

func (c *Cx1Client) GetExportStatusByID(exportID string) (ExportStatus, error) {
	var response ExportStatus

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sca/export/requests?exportId=%v", exportID), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch export status for exportID %v: %s", exportID, err)
		return response, fmt.Errorf("failed to fetch export status for exportID %v: %s", exportID, err)
	}

	err = json.Unmarshal([]byte(data), &response)
	return response, err
}

func (c *Cx1Client) DownloadExport(exportUrl string) ([]byte, error) {
	data, err := c.sendRequestInternal(http.MethodGet, exportUrl, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to download export from url %v: %s", exportUrl, err)
	}
	return data, nil
}

// convenience function, polls and returns the URL to download the export
func (c *Cx1Client) ExportPollingByID(exportID string) (string, error) {
	return c.ExportPollingByIDWithTimeout(exportID, c.consts.ExportPollingDelaySeconds, c.consts.ExportPollingMaxSeconds)
}

func (c *Cx1Client) ExportPollingByIDWithTimeout(exportID string, delaySeconds, maxSeconds int) (string, error) {
	pollingCounter := 0
	for {
		status, err := c.GetExportStatusByID(exportID)
		if err != nil {
			return "", err
		}

		if strings.EqualFold(status.Status, "completed") {
			return status.ExportURL, nil
		} else if strings.EqualFold(status.Status, "failed") {
			return "", fmt.Errorf("export generation failed")
		}

		if maxSeconds != 0 && pollingCounter > maxSeconds {
			return "", fmt.Errorf("export %v polling reached %d seconds, aborting - use cx1client.get/setclientvars to change", ShortenGUID(exportID), pollingCounter)
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}
