package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// refer to https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/qf8welz2tlx8a-retrieve-analytics-kpi-data
// Note that this is the "generic" internal function and so it is up to the consumer to unmarshal the response to the correct type
// you can use the other analytics convenience functions to do this for you
func (c *Cx1Client) getAnalytics(kpi string, limit uint64, offset *uint64, filter AnalyticsFilter) ([]byte, error) {
	c.logger.Debugf("Fetching Analytics KPI %v", kpi)
	var response []byte
	type requestBodyStruct struct {
		AnalyticsFilter
		KPI    string  `json:"kpi"`
		Limit  uint64  `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
	}

	requestBody := requestBodyStruct{
		AnalyticsFilter: filter,
		KPI:             kpi,
		Limit:           limit,
		Offset:          offset,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return response, err
	}

	return c.sendRequest(http.MethodPost, "/data_analytics/analyticsAPI/v1", bytes.NewReader(jsonBody), nil)
}

func (c *Cx1Client) getAnalyticsDistributionStats(kpi string, filter AnalyticsFilter) (AnalyticsDistributionStats, error) {
	var stats AnalyticsDistributionStats
	bytes, err := c.getAnalytics(kpi, 0, nil, filter)
	if err != nil {
		return stats, err
	}
	err = json.Unmarshal(bytes, &stats)
	return stats, err
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesBySeverityTotal(filter AnalyticsFilter) (AnalyticsDistributionStats, error) {
	return c.getAnalyticsDistributionStats("vulnerabilitiesBySeverityTotal", filter)
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesByStateTotal(filter AnalyticsFilter) (AnalyticsDistributionStats, error) {
	return c.getAnalyticsDistributionStats("vulnerabilitiesByStateTotal", filter)
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesByStatusTotal(filter AnalyticsFilter) (AnalyticsDistributionStats, error) {
	return c.getAnalyticsDistributionStats("vulnerabilitiesByStatusTotal", filter)
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesBySeverityAndStateTotal(filter AnalyticsFilter) ([]AnalyticsSeverityAndStateStats, error) {
	var stats []AnalyticsSeverityAndStateStats
	bytes, err := c.getAnalytics("vulnerabilitiesBySeverityAndStateTotal", 0, nil, filter)
	if err != nil {
		return stats, err
	}

	err = json.Unmarshal(bytes, &stats)
	return stats, err
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesByAgingTotal(filter AnalyticsFilter) ([]AnalyticsAgingStats, error) {
	var response struct {
		AgingAndSeverities []AnalyticsAgingStats `json:"agingAndSeverities"`
	}
	bytes, err := c.getAnalytics("agingTotal", 0, nil, filter)
	if err != nil {
		return response.AgingAndSeverities, err
	}

	err = json.Unmarshal(bytes, &response)
	return response.AgingAndSeverities, err
}

func (c *Cx1Client) getAnalyticsOverTimeStats(kpi string, filter AnalyticsFilter) ([]AnalyticsOverTimeStats, error) {
	var response struct {
		Distribution []AnalyticsOverTimeStats `json:"distribution"`
	}

	bytes, err := c.getAnalytics(kpi, 0, nil, filter)
	if err != nil {
		return response.Distribution, err
	}
	err = json.Unmarshal(bytes, &response)
	return response.Distribution, err
}

func (c *Cx1Client) GetAnalyticsVulnerabilitiesBySeverityOvertime(filter AnalyticsFilter) ([]AnalyticsOverTimeStats, error) {
	return c.getAnalyticsOverTimeStats("vulnerabilitiesBySeverityOvertime", filter)
}

func (c *Cx1Client) GetAnalyticsFixedVulnerabilitiesBySeverityOvertime(filter AnalyticsFilter) ([]AnalyticsOverTimeStats, error) {
	return c.getAnalyticsOverTimeStats("fixedVulnerabilitiesBySeverityOvertime", filter)
}

func (c *Cx1Client) GetAnalyticsMeanTimeToResolution(filter AnalyticsFilter) (AnalyticsMeanTimeStats, error) {
	var stats AnalyticsMeanTimeStats
	bytes, err := c.getAnalytics("meanTimeToResolution", 0, nil, filter)
	if err != nil {
		return stats, err
	}
	err = json.Unmarshal(bytes, &stats)
	return stats, err
}

func (c *Cx1Client) getAnalyticsVulnerabilityStats(kpi string, limit uint64, filter AnalyticsFilter) ([]AnalyticsVulnerabilitiesStats, error) {
	var stats []AnalyticsVulnerabilitiesStats
	bytes, err := c.getAnalytics(kpi, limit, nil, filter)
	if err != nil {
		return stats, err
	}
	err = json.Unmarshal(bytes, &stats)
	return stats, err
}

func (c *Cx1Client) getAnalyticsPagedVulnerabilityStats(kpi string, limit uint64, offset uint64, filter AnalyticsFilter) ([]AnalyticsVulnerabilitiesStats, error) {

	var pagedResponse struct {
		AllVulnerabilities []AnalyticsVulnerabilitiesStats `json:"allVulnerabilities"`
		Page               int                             `json:"page"` // this field is largely useless
	}

	bytes, err := c.getAnalytics(kpi, limit, &offset, filter)
	if err != nil {
		return pagedResponse.AllVulnerabilities, err
	}
	err = json.Unmarshal(bytes, &pagedResponse)
	return pagedResponse.AllVulnerabilities, err
}

func (c *Cx1Client) GetAnalyticsMostCommonVulnerabilities(limit uint64, filter AnalyticsFilter) ([]AnalyticsVulnerabilitiesStats, error) {
	return c.getAnalyticsVulnerabilityStats("mostCommonVulnerabilities", limit, filter)
}

func (c *Cx1Client) GetAnalyticsAllVulnerabilities(limit uint64, offset uint64, filter AnalyticsFilter) ([]AnalyticsVulnerabilitiesStats, error) {
	return c.getAnalyticsPagedVulnerabilityStats("allVulnerabilities", limit, offset, filter)
}

func (c *Cx1Client) GetAnalyticsMostAgingVulnerabilities(limit uint64, filter AnalyticsFilter) ([]AnalyticsVulnerabilitiesStats, error) {
	return c.getAnalyticsVulnerabilityStats("mostAgingVulnerabilities", limit, filter)
}

func (c *Cx1Client) GetAnalyticsIDEOverTimeStats() ([]AnalyticsIDEOverTimeDistribution, error) {
	var response struct {
		Distribution []AnalyticsIDEOverTimeDistribution `json:"distribution"`
	}

	bytes, err := c.getAnalytics("ideOvertime", 0, nil, AnalyticsFilter{})
	if err != nil {
		return response.Distribution, err
	}
	err = json.Unmarshal(bytes, &response)
	return response.Distribution, err
}

func (c *Cx1Client) GetAnalyticsIDETotal() ([]AnalyticsIDEStatEntry, error) {
	var response struct {
		IDEData []AnalyticsIDEStatEntry `json:"ideData"`
	}

	bytes, err := c.getAnalytics("ideTotal", 0, nil, AnalyticsFilter{})
	if err != nil {
		return response.IDEData, err
	}
	err = json.Unmarshal(bytes, &response)
	return response.IDEData, err
}

const AnalyticsTimeLayout = "2006-01-02 15:04:05"

func (ct *AnalyticsTime) UnmarshalJSON(b []byte) error {
	// Trim quotes from the JSON string.
	s := string(b[1 : len(b)-1])

	var err error
	ct.Time, err = time.Parse(AnalyticsTimeLayout, s)
	if err == nil {
		return nil
	}

	return fmt.Errorf("failed to parse time: %v", err)
}

// MarshalJSON implements the json.Marshaler interface.
func (ct AnalyticsTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(ct.Time.Format(AnalyticsTimeLayout))
}
