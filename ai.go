package Cx1ClientGo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Message parsed from the GET /ssegateway/remediation-status stream
type aiRemediationStatus struct {
	CurrentPhase string  `json:"currentPhase"`
	Percentage   float64 `json:"percentage"`
	JobRunning   bool    `json:"jobRunning"`
}

// Triggers AI remediation for one specific engine result
// An error is returned if the request fails or the server does not respond with status "accepted".
func (c *Cx1Client) RequestAIRemediation(scanId, projectId, engine, resultId string) (string, error) {

	type AIRemediationRequest struct {
		ScanID    string                       `json:"scanID"`
		ProjectID string                       `json:"projectID"`
		Buckets   []AIRemediationRequestBucket `json:"buckets"`
	}

	request := AIRemediationRequest{
		ScanID:    scanId,
		ProjectID: projectId,
		Buckets: []AIRemediationRequestBucket{
			{
				ScannerType: engine,
				ResultIDs:   []string{resultId},
			},
		},
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
// messages from it until the job reports it is no longer running (or the stream ends).
// Returns the last status message received.
func (c *Cx1Client) PollAIRemediationStatus(scanID, engine, resultID string) (string, error) {
	var status aiRemediationStatus

	endpoint := fmt.Sprintf("/ssegateway/remediation-status?engine=%v&scanId=%v&resultHash=%v",
		url.QueryEscape(engine), url.QueryEscape(scanID), url.QueryEscape(resultID))

	response, err := c.sendRequestRawCx1(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return status.CurrentPhase, fmt.Errorf("failed to open AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
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
			return status.CurrentPhase, fmt.Errorf("failed to parse AI remediation status message %q: %s", payload, err)
		}

		c.config.Logger.Tracef("AI remediation status for scan %v, result %v: phase=%v percentage=%v jobRunning=%v",
			scanID, resultID, status.CurrentPhase, status.Percentage, status.JobRunning)

		if !status.JobRunning {
			return status.CurrentPhase, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return status.CurrentPhase, fmt.Errorf("error reading AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
	}

	return status.CurrentPhase, nil
}

// Fetches the completed AI remediation details (analysis, suggested diffs, generated tests) for one result.
func (c *Cx1Client) GetAIRemediationDetails(scanID, resultID string) (AIRemediationDetails, error) {
	var details AIRemediationDetails

	endpoint := fmt.Sprintf("/remediation/remediation-details/%v/%v", scanID, url.QueryEscape(resultID))

	data, err := c.sendRequest(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return details, fmt.Errorf("failed to get AI remediation details for scan %v, result %v: %s", scanID, resultID, err)
	}

	err = json.Unmarshal(data, &details)
	return details, err
}
