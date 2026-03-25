package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
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
