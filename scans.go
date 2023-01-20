package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
)

// Scans
// GetScans returns all scan status on the project addressed by projectID
// todo cleanup systeminstance
func (c *Cx1Client) GetScan(scanID string) (Scan, error) {
	var scan Scan

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans/%v", scanID), nil, nil)
	if err != nil {
		c.logger.Errorf("Failed to fetch scan with ID %v: %s", scanID, err)
		return scan, errors.Wrapf(err, "failed to fetch scan with ID %v", scanID)
	}

	json.Unmarshal([]byte(data), &scan)
	return scan, nil
}

func (c *Cx1Client) GetScanMetadata(scanID string) (ScanMetadata, error) {
	var scanmeta ScanMetadata

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-metadata/%v", scanID), nil, http.Header{})
	if err != nil {
		c.logger.Errorf("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
		return scanmeta, errors.Wrapf(err, "failed to fetch metadata for scan with ID %v", scanID)
	}

	json.Unmarshal(data, &scanmeta)
	return scanmeta, nil
}

func (s *ScanSummary) TotalCount() uint64 {
	var count uint64
	count = 0

	for _, c := range s.SASTCounters.StateCounters {
		count += c.Counter
	}

	return count
}

func (c *Cx1Client) GetScanSummary(scanID string) (ScanSummary, error) {
	var ScansSummaries struct {
		ScanSum    []ScanSummary `json:"scansSummaries"`
		TotalCount uint64
	}

	params := url.Values{
		"scan-ids":                {scanID},
		"include-queries":         {"false"},
		"include-status-counters": {"true"},
		"include-files":           {"false"},
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scan-summary/?%v", params.Encode()), nil, http.Header{})
	if err != nil {
		c.logger.Errorf("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
		return ScanSummary{}, errors.Wrapf(err, "failed to fetch metadata for scan with ID %v", scanID)
	}

	err = json.Unmarshal(data, &ScansSummaries)

	if err != nil {
		return ScanSummary{}, err
	}
	if ScansSummaries.TotalCount == 0 {
		return ScanSummary{}, errors.New(fmt.Sprintf("Failed to retrieve scan summary for scan ID %v", scanID))
	}

	if len(ScansSummaries.ScanSum) == 0 {
		c.logger.Errorf("Failed to parse data, 0-len ScanSum.\n%v", string(data))
		return ScanSummary{}, errors.New("Fail")
	}

	return ScansSummaries.ScanSum[0], nil
}

func (c *Cx1Client) GetScanLogs(scanID, engine string) ([]byte, error) {
	c.logger.Debugf("Fetching scan logs for scan %v", scanID)

	response, err := c.sendRequestRawCx1(http.MethodGet, fmt.Sprintf("/logs/%v/%v", scanID, engine), nil, nil)

	if err != nil {
		c.logger.Errorf("Error retrieving scanlog url: %s", err)
		return []byte{}, err
	}

	enginelogURL := response.Header.Get("Location")
	if enginelogURL == "" {
		return []byte{}, errors.New("Expected location header response not found")
	}

	c.logger.Infof("Retrieved url: %v", enginelogURL)
	data, err := c.sendRequestInternal(http.MethodGet, enginelogURL, nil, nil)
	if err != nil {
		c.logger.Errorf("Failed to download logs from %v: %s", enginelogURL, err)
		return []byte{}, nil
	}

	return data, nil
}

func (c *Cx1Client) scanProject(scanConfig map[string]interface{}) (Scan, error) {
	scan := Scan{}

	jsonBody, err := json.Marshal(scanConfig)
	if err != nil {
		return scan, err
	}

	data, err := c.sendRequest(http.MethodPost, "/scans", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return scan, err
	}

	err = json.Unmarshal(data, &scan)
	return scan, err
}

func (c *Cx1Client) ScanProjectZip(projectID, sourceUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	jsonBody := map[string]interface{}{
		"project": map[string]interface{}{"id": projectID},
		"type":    "upload",
		"tags":    tags,
		"handler": map[string]interface{}{
			"uploadurl": sourceUrl,
			"branch":    branch,
		},
		"config": settings,
	}

	scan, err := c.scanProject(jsonBody)
	if err != nil {
		return scan, errors.Wrapf(err, "Failed to start a zip scan for project %v", projectID)
	}
	return scan, err
}

func (c *Cx1Client) ScanProjectGit(projectID, repoUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	jsonBody := map[string]interface{}{
		"project": map[string]interface{}{"id": projectID},
		"type":    "git",
		"tags":    tags,
		"handler": map[string]interface{}{
			"repoUrl": repoUrl,
			"branch":  branch,
		},
		"config": settings,
	}

	scan, err := c.scanProject(jsonBody)
	if err != nil {
		return scan, errors.Wrapf(err, "Failed to start a git scan for project %v", projectID)
	}
	return scan, err
}

// convenience function
func (c *Cx1Client) ScanProject(projectID, sourceUrl, branch, scanType string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	if scanType == "upload" {
		return c.ScanProjectZip(projectID, sourceUrl, branch, settings, tags)
	} else if scanType == "git" {
		return c.ScanProjectGit(projectID, sourceUrl, branch, settings, tags)
	}

	return Scan{}, errors.New("Invalid scanType provided, must be 'upload' or 'git'")
}

// convenience function
func (s *Scan) IsIncremental() (bool, error) {
	for _, scanconfig := range s.Metadata.Configs {
		if scanconfig.ScanType == "sast" {
			if val, ok := scanconfig.Values["incremental"]; ok {
				return val == "true", nil
			}
		}
	}
	return false, errors.New(fmt.Sprintf("Scan %v did not have a sast-engine incremental flag set", s.ScanID))
}

// convenience
func (c *Cx1Client) ScanPolling(s *Scan) (Scan, error) {
	c.logger.Infof("Polling status of scan %v", s.ScanID)
	var err error
	scan := *s
	for scan.Status == "Running" {
		time.Sleep(10 * time.Second)
		scan, err = c.GetScan(scan.ScanID)
		if err != nil {
			c.logger.Errorf("Failed to get scan status: %v", err)
			return scan, err
		}
		c.logger.Infof(" - %v", scan.Status)
		if scan.Status != "Running" {
			break
		}
	}
	return scan, nil
}

func (c *Cx1Client) GetUploadURL() (string, error) {
	c.logger.Debug("Get Cx1 Upload URL")
	response, err := c.sendRequest(http.MethodPost, "/uploads", nil, nil)

	if err != nil {
		c.logger.Errorf("Unable to get Upload URL: %s", err)
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(response, &jsonBody)
	if err != nil {
		c.logger.Errorf("Error: %s", err)
		c.logger.Tracef("Input was: %s", string(response))
		return "", err
	} else {
		return jsonBody["url"].(string), nil
	}
}

func (c *Cx1Client) PutFile(URL string, filename string) (string, error) {
	c.logger.Tracef("Putting file %v to %v", filename, URL)

	fileContents, err := os.ReadFile(filename)
	if err != nil {
		c.logger.Errorf("Failed to Read the File %v: %s", filename, err)
		return "", err
	}

	cx1_req, err := http.NewRequest(http.MethodPut, URL, bytes.NewReader(fileContents))
	if err != nil {
		c.logger.Errorf("Error: %s", err)
		return "", err
	}

	cx1_req.Header.Add("Content-Type", "application/zip")
	cx1_req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", c.authToken))
	cx1_req.ContentLength = int64(len(fileContents))

	res, err := c.httpClient.Do(cx1_req)
	if err != nil {
		c.logger.Errorf("Error: %s", err)
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		c.logger.Errorf("Error: %s", err)
		return "", err
	}

	return string(resBody), nil
}

func (s *Scan) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(s.ScanID), s.ProjectName)
}