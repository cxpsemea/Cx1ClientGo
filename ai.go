package Cx1ClientGo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Message parsed from the GET /ssegateway/remediation-status stream
type aiRemediationStatus struct {
	CurrentPhase string  `json:"currentPhase"`
	Percentage   float64 `json:"percentage"`
	JobRunning   bool    `json:"jobRunning"`
}

// Triggers AI remediation for one specific engine result
// An error is returned if the request fails or the server does not respond with status "accepted".
func (c *Cx1Client) RequestAIRemediation(scanId, projectId, engine, alternateId string) (string, error) {
	buckets := []AIRequestBucket{
		{
			Engine:       engine,
			AlternateIDs: []string{alternateId},
		},
	}

	return c.RequestAIRemediations(scanId, projectId, buckets)
}

func (c *Cx1Client) RequestAIRemediations(scanId, projectId string, engineResults []AIRequestBucket) (string, error) {
	type AIRemediationRequest struct {
		ScanID    string            `json:"scanID"`
		ProjectID string            `json:"projectID"`
		Buckets   []AIRequestBucket `json:"buckets"`
	}

	request := AIRemediationRequest{
		ScanID:    scanId,
		ProjectID: projectId,
		Buckets:   engineResults,
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/remediation/remediate", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to request AI remediation for scan %v: %s", request.ScanID, err)
	}

	// Response to the initial POST /remediation/remediate request
	type AIRemediationResponse struct {
		Status           string  `json:"status"`
		Published        bool    `json:"published"`
		ExistingState    *string `json:"existingState"`
		RemediationJobId string  `json:"remediationJobId"`
	}

	var response AIRemediationResponse
	if err = json.Unmarshal(data, &response); err != nil {
		return "", err
	}

	if response.Status != "accepted" {
		return "", fmt.Errorf("AI remediation request for scan %v was not accepted, status: %v", request.ScanID, response.Status)
	}

	return response.RemediationJobId, nil
}

// Opens the ssegateway status stream for a single result's remediation job and reads
// messages from it until the job reports it is no longer running or the stream ends.
// Returns the last status message received and whether the job was seen to finish.
func (c *Cx1Client) pollAIRemediationStatusOnce(scanID, engine, resultID string) (string, bool, error) {
	var status aiRemediationStatus

	endpoint := fmt.Sprintf("/ssegateway/remediation-status?engine=%v&scanId=%v&resultHash=%v",
		url.QueryEscape(engine), url.QueryEscape(scanID), url.QueryEscape(resultID))

	response, err := c.sendRequestRawCx1(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return status.CurrentPhase, false, fmt.Errorf("failed to open AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
	}
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var payload string
		switch {
		case strings.HasPrefix(line, "data:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case strings.HasPrefix(line, "message:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "message:"))
		default:
			continue
		}

		if err := json.Unmarshal([]byte(payload), &status); err != nil {
			return status.CurrentPhase, false, fmt.Errorf("failed to parse AI remediation status message %q: %s", payload, err)
		}

		c.config.Logger.Tracef("AI remediation status for scan %v, result %v: phase=%v percentage=%v jobRunning=%v",
			scanID, resultID, status.CurrentPhase, status.Percentage, status.JobRunning)

		if !status.JobRunning {
			return status.CurrentPhase, true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return status.CurrentPhase, false, fmt.Errorf("error reading AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
	}

	return status.CurrentPhase, false, nil
}

// Poll an AI remediation job periodically until it finishes, or the default timeout is reached.
// The default timeout can be accessed via Get/SetClientVars
func (c *Cx1Client) PollAIRemediationStatus(scanID, engine, resultID string) (string, error) {
	return c.PollAIRemediationStatusWithTimeout(scanID, engine, resultID, c.config.Polling.AIPollingDelaySeconds, c.config.Polling.AIPollingMaxSeconds)
}

// Poll an AI remediation job periodically until it finishes, or the specified timeout is reached.
// Each attempt opens the ssegateway status stream and reads from it until the job finishes or the
// stream ends; if the stream ends before the job finishes, it is reopened after delaySeconds.
func (c *Cx1Client) PollAIRemediationStatusWithTimeout(scanID, engine, resultID string, delaySeconds, maxSeconds int) (string, error) {
	c.config.Logger.Infof("Polling AI remediation status for scan %v, result %v", scanID, resultID)

	pollingCounter := 0
	for {
		phase, finished, err := c.pollAIRemediationStatusOnce(scanID, engine, resultID)
		if err != nil {
			return phase, err
		}
		if finished {
			return phase, nil
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return phase, fmt.Errorf("AI remediation status polling for scan %v, result %v reached %d seconds, aborting - use cx1client.get/setclientvars to change", scanID, resultID, pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}

// Fetches the completed AI remediation details (analysis, suggested diffs, generated tests) for one result.
// There can be a short delay between the status-polling endpoint reporting a job as finished and this
// endpoint returning the full result data, so this retries internally using fixed, non-configurable
// polling variables (AIRemediationDetailsPollingMaxSeconds/AIRemediationDetailsPollingDelaySeconds) -
// this delay is considered a platform quirk rather than a normal, user-controllable polling process.
func (c *Cx1Client) GetAIRemediationDetails(scanID, resultID string) (AIRemediationDetails, error) {
	delaySeconds := c.config.Polling.AIDetailsPollingDelaySeconds
	maxSeconds := c.config.Polling.AIDetailsPollingMaxSeconds

	pollingCounter := 0
	for {
		details, err := c.getAIRemediationDetails(scanID, resultID)
		if err != nil {
			return details, err
		}

		stillInProgress := false
		for _, result := range details.Results {
			if result.JobStatus == "IN_PROGRESS" {
				stillInProgress = true
				break
			}
		}
		if !stillInProgress {
			return details, nil
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return details, fmt.Errorf("AI remediation details for scan %v, result %v were still in progress after %d seconds, aborting", scanID, resultID, pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}

func (c *Cx1Client) getAIRemediationDetails(scanID, resultID string) (AIRemediationDetails, error) {
	var details AIRemediationDetails

	endpoint := fmt.Sprintf("/remediation/remediation-details/%v/%v", scanID, url.QueryEscape(resultID))

	data, err := c.sendRequest(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return details, fmt.Errorf("failed to get AI remediation details for scan %v, result %v: %s", scanID, resultID, err)
	}

	err = json.Unmarshal(data, &details)
	return details, err
}

// Fetches the tenant's current AI credits balance and consumption/enforcement state.
func (c *Cx1Client) GetAICreditsInfo() (AICreditsInfo, error) {
	var info AICreditsInfo

	data, err := c.sendRequest(http.MethodGet, "/credits/info", nil, nil)
	if err != nil {
		return info, fmt.Errorf("failed to get AI credits info: %s", err)
	}

	err = json.Unmarshal(data, &info)
	return info, err
}

// Fetches the tenant's AI license/trial status.
func (c *Cx1Client) GetAILicenseInfo() (AILicenseInfo, error) {
	var info AILicenseInfo

	data, err := c.sendRequest(http.MethodGet, "/credits/license/status", nil, nil)
	if err != nil {
		return info, fmt.Errorf("failed to get AI license info: %s", err)
	}

	err = json.Unmarshal(data, &info)
	return info, err
}

// Triggers AI triage for one specific engine result
// An error is returned if the request fails or the server does not respond with status "accepted".
func (c *Cx1Client) RequestAITriage(scanId, engine, alternateId string) (string, error) {
	buckets := []AIRequestBucket{
		{
			Engine:       engine,
			AlternateIDs: []string{alternateId},
		},
	}

	return c.RequestAITriages(scanId, buckets)
}

func (c *Cx1Client) RequestAITriages(scanId string, engineResults []AIRequestBucket) (string, error) {
	type AITriageRequest struct {
		ScanID  string            `json:"scanID"`
		Buckets []AIRequestBucket `json:"buckets"`
	}

	request := AITriageRequest{
		ScanID:  scanId,
		Buckets: engineResults,
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/ai-triage/triage", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to request AI triage for scan %v: %s", request.ScanID, err)
	}

	// Response to the initial POST /ai-triage/triage request
	type AITriageResponse struct {
		ScanID              string  `json:"scanID"`
		Status              string  `json:"status"`
		TriageID            string  `json:"triageID"`
		Published           bool    `json:"published"`
		ExistingTriageState *string `json:"existingTriageState"`
	}

	var response AITriageResponse
	if err = json.Unmarshal(data, &response); err != nil {
		return "", err
	}

	if response.Status != "accepted" {
		return "", fmt.Errorf("AI triage request for scan %v was not accepted, status: %v", request.ScanID, response.Status)
	}

	return response.TriageID, nil
}

// Message parsed from the GET /ssegateway/triage-status stream
type aiTriageStatus struct {
	CurrentPhase string  `json:"currentPhase"`
	Percentage   float64 `json:"percentage"`
	JobRunning   bool    `json:"jobRunning"`
}

// Opens the ssegateway status stream for a single result's triage job and reads
// messages from it until the job reports it is no longer running or the stream ends.
// Returns the last status message received and whether the job was seen to finish.
func (c *Cx1Client) pollAITriageStatusOnce(projectId, engine, similarityId string) (string, bool, error) {
	var status aiTriageStatus

	// groupId in the query string is the finding's similarityId
	endpoint := fmt.Sprintf("/ssegateway/triage-status?engine=%v&groupId=%v&projectId=%v",
		url.QueryEscape(engine), url.QueryEscape(similarityId), url.QueryEscape(projectId))

	response, err := c.sendRequestRawCx1(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return status.CurrentPhase, false, fmt.Errorf("failed to open AI triage status stream for project %v, result %v: %s", projectId, similarityId, err)
	}
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var payload string
		switch {
		case strings.HasPrefix(line, "data:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case strings.HasPrefix(line, "message:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "message:"))
		default:
			continue
		}

		if err := json.Unmarshal([]byte(payload), &status); err != nil {
			return status.CurrentPhase, false, fmt.Errorf("failed to parse AI triage status message %q: %s", payload, err)
		}

		c.config.Logger.Tracef("AI triage status for project %v, result %v: phase=%v percentage=%v jobRunning=%v",
			projectId, similarityId, status.CurrentPhase, status.Percentage, status.JobRunning)

		if !status.JobRunning {
			return status.CurrentPhase, true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return status.CurrentPhase, false, fmt.Errorf("error reading AI triage status stream for project %v, result %v: %s", projectId, similarityId, err)
	}

	return status.CurrentPhase, false, nil
}

// Poll an AI triage job periodically until it finishes, or the default timeout is reached.
// The default timeout can be accessed via Get/SetClientVars - it shares its polling variables
// with PollAIRemediationStatus.
func (c *Cx1Client) PollAITriageStatus(projectId, engine, similarityId string) (string, error) {
	return c.PollAITriageStatusWithTimeout(projectId, engine, similarityId, c.config.Polling.AIPollingDelaySeconds, c.config.Polling.AIPollingMaxSeconds)
}

// Poll an AI triage job periodically until it finishes, or the specified timeout is reached.
// Each attempt opens the ssegateway status stream and reads from it until the job finishes or the
// stream ends; if the stream ends before the job finishes, it is reopened after delaySeconds.
func (c *Cx1Client) PollAITriageStatusWithTimeout(projectId, engine, similarityId string, delaySeconds, maxSeconds int) (string, error) {
	c.config.Logger.Infof("Polling AI triage status for project %v, result %v", projectId, similarityId)

	pollingCounter := 0
	for {
		phase, finished, err := c.pollAITriageStatusOnce(projectId, engine, similarityId)
		if err != nil {
			return phase, err
		}
		if finished {
			return phase, nil
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return phase, fmt.Errorf("AI triage status polling for project %v, result %v reached %d seconds, aborting - use cx1client.get/setclientvars to change", projectId, similarityId, pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}

// Fetches the completed AI triage details (analysis, reasoning trace) for one result.
// As with GetAIRemediationDetails, there can be a short delay between the status-polling endpoint
// reporting a job as finished and this endpoint returning the full result data, so this retries
// internally using the same fixed, non-configurable polling variables as GetAIRemediationDetails.
func (c *Cx1Client) GetAITriageDetails(projectId, similarityId string) (AITriageDetails, error) {
	delaySeconds := c.config.Polling.AIDetailsPollingDelaySeconds
	maxSeconds := c.config.Polling.AIDetailsPollingMaxSeconds

	pollingCounter := 0
	for {
		details, err := c.getAITriageDetails(projectId, similarityId)
		if err != nil {
			return details, err
		}

		if details.JobStatus != "IN_PROGRESS" {
			return details, nil
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return details, fmt.Errorf("AI triage details for project %v, result %v were still in progress after %d seconds, aborting", projectId, similarityId, pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
}

func (c *Cx1Client) getAITriageDetails(projectId, similarityId string) (AITriageDetails, error) {
	var details AITriageDetails

	endpoint := fmt.Sprintf("/ai-triage/triage/%v/%v", url.QueryEscape(projectId), url.QueryEscape(similarityId))

	data, err := c.sendRequest(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return details, fmt.Errorf("failed to get AI triage details for project %v, result %v: %s", projectId, similarityId, err)
	}

	err = json.Unmarshal(data, &details)
	return details, err
}
