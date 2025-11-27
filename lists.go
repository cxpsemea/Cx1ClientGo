package Cx1ClientGo

import (
	"encoding/json"
	"net/http"
)

// lists of constants from cx1

func (c *Cx1Client) GetResultStates() ([]string, error) {
	c.logger.Debugf("Getting result states")
	var states []string

	data, err := c.sendRequest(http.MethodGet, "/lists/states", nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching states failed: %s", err)
		return states, err
	}

	err = json.Unmarshal(data, &states)
	return states, err
}

func (c *Cx1Client) GetResultStatuses() ([]string, error) {
	c.logger.Debugf("Getting result statuses")
	var statuses []string

	data, err := c.sendRequest(http.MethodGet, "/lists/statuses", nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching statuses failed: %s", err)
		return statuses, err
	}

	err = json.Unmarshal(data, &statuses)
	return statuses, err
}

func (c *Cx1Client) GetResultSeverities() ([]string, error) {
	c.logger.Debugf("Getting severities")
	var severities []string

	data, err := c.sendRequest(http.MethodGet, "/lists/severities", nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching severities failed: %s", err)
		return severities, err
	}

	err = json.Unmarshal(data, &severities)
	return severities, err
}
