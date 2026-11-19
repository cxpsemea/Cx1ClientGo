package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func (c *Cx1Client) GetSCMIntegrations() ([]SCMIntegration, error) {
	data, err := c.sendRequest(http.MethodGet, "/repos-manager/v2/scms?fields=repoCount", nil, http.Header{})
	if err != nil {
		return nil, err
	}

	var integrations []SCMIntegration
	err = json.Unmarshal(data, &integrations)
	return integrations, err
}

func (c *Cx1Client) GetSCMRepository(repositoryID uint64) (SCMRepository, error) {
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/repos-manager/repo/%d", repositoryID), nil, http.Header{})
	if err != nil {
		return SCMRepository{}, err
	}

	var repository SCMRepository
	err = json.Unmarshal(data, &repository)
	return repository, err
}

// SCMProjectScanRequest is the body for POST /repos-manager/scms/{scmId}/orgs/{org}/repo/projectScan
type SCMProjectScanRequest struct {
	RepoOrigin string             `json:"repoOrigin"` // eg: github
	Project    SCMProjectScanInfo `json:"project"`
	OrgSSHKey  *string            `json:"orgSshKey"`
}

type SCMProjectScanInfo struct {
	RepoIdentity      string   `json:"repoIdentity"` // repository name
	ProjectID         string   `json:"projectId"`
	DefaultBranch     string   `json:"defaultBranch"`
	ScannerTypes      []string `json:"scannerTypes"` // sast, sca, kics, apisec, containers
	RepoID            string   `json:"repoId"`
	IsIncrementalScan bool     `json:"isIncrementalScan"`
}

// ScanProjectBySCM triggers a scan of an SCM-imported project through the repos-manager.
// The raw response body is returned as the response format is not defined.
func (c *Cx1Client) ScanProjectBySCM(scmID uint64, org string, request SCMProjectScanRequest) ([]byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return c.sendRequest(http.MethodPost, fmt.Sprintf("/repos-manager/scms/%d/orgs/%s/repo/projectScan?projectId=%s", scmID, url.PathEscape(org), url.QueryEscape(request.Project.ProjectID)), bytes.NewReader(body), http.Header{})
}
