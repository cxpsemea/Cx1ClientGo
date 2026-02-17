package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
)

func (c *Cx1Client) GetScanResultsByID(scanID string, limit uint64) (ScanResultSet, error) {
	c.config.Logger.Debugf("Get %d Cx1 Scan Results for scan %v", limit, scanID)

	_, results, err := c.GetXScanResultsFiltered(ScanResultsFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Results},
		ScanID:     scanID,
	}, limit)

	return results, err
}

func (c *Cx1Client) GetAllScanResultsByID(scanID string) (ScanResultSet, error) {
	c.config.Logger.Debugf("Get all Cx1 Scan Results for scan %v", scanID)

	_, results, err := c.GetAllScanResultsFiltered(ScanResultsFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Results},
		ScanID:     scanID,
	})

	return results, err
}

func (c *Cx1Client) GetScanResultsCountByID(scanID string) (uint64, error) {
	c.config.Logger.Debugf("Get Cx1 Scan Results count for scan %v", scanID)
	count, _, err := c.GetScanResultsFiltered(ScanResultsFilter{
		BaseFilter: BaseFilter{Limit: 0},
		ScanID:     scanID,
	})

	return count, err
}

// returns one 'page' of scan results matching the filter
// returns items (filter.Offset*filter.Limit) to (filter.Offset + 1)*filter.Limit
// returns the count of items retrieved, however some items may not be parsed into the result
// set depending on support in cx1clientgo
func (c *Cx1Client) GetScanResultsFiltered(filter ScanResultsFilter) (uint64, ScanResultSet, error) {
	params, _ := query.Values(filter)

	results := ScanResultSet{}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/results/?%v", params.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch scans matching filter %v: %s", params.Encode(), err)
		c.config.Logger.Tracef("Error: %s", err)
		return 0, results, err
	}

	count, results, err := c.parseScanResults(filter.ScanID, data)
	return count, results, err
}

func (s *ScanResultsFilter) Bump() { // this one does offset in pages rather than items
	s.Offset++
}

// gets all of the results available matching a filter
// the counter returned represents the total number of results which were parsed
// this may not include some of the returned results depending on Cx1ClientGo support
func (c *Cx1Client) GetAllScanResultsFiltered(filter ScanResultsFilter) (uint64, ScanResultSet, error) {
	var results ScanResultSet

	count, rs, err := c.GetScanResultsFiltered(filter)
	results = rs

	for err == nil && count > (filter.Offset+1)*filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, rs, err = c.GetScanResultsFiltered(filter)
		results.Append(&rs)
	}

	return results.Count(), results, err
}

// will return at least X results matching the filter
// May return more due to paging eg: requesting 101 with a 100-item page can return 200 results
func (c *Cx1Client) GetXScanResultsFiltered(filter ScanResultsFilter, desiredcount uint64) (uint64, ScanResultSet, error) {
	var results ScanResultSet

	_, rs, err := c.GetScanResultsFiltered(filter)
	results = rs

	for err == nil && desiredcount > (filter.Offset+1)*filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, rs, err = c.GetScanResultsFiltered(filter)
		results.Append(&rs)
	}

	return results.Count(), results, err
}

// Note: when creating SAST overrides, you cannot change multiple fields at once unless mandatory.
// For example, changing state to "Confirmed" and adding a comment-text requires two predicates, 1 "Confirmed" + 1 comment
func (r ScanSASTResult) CreateResultsPredicate(projectId, scanId string) SASTResultsPredicates {
	return SASTResultsPredicates{
		ResultsPredicatesBase{
			SimilarityID: r.SimilarityID,
			ProjectID:    projectId,
			ScanID:       scanId,
			//State:     r.State,
			//Severity:  r.Severity,
		},
	}
}
func (r ScanIACResult) CreateResultsPredicate(projectId, scanId string) IACResultsPredicates {
	return IACResultsPredicates{
		ResultsPredicatesBase{
			SimilarityID: r.SimilarityID,
			ProjectID:    projectId,
			ScanID:       scanId,
			State:        r.State,
			Severity:     r.Severity,
		},
	}
}

// results
func (c *Cx1Client) AddSASTResultsPredicates(predicates []SASTResultsPredicates) error {
	c.config.Logger.Debugf("Adding %d SAST results predicates", len(predicates))

	jsonBody, err := json.Marshal(predicates)
	if err != nil {
		c.config.Logger.Tracef("Failed to add SAST results predicates: %s", err)
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/sast-results-predicates", bytes.NewReader(jsonBody), nil)
	return err
}
func (c *Cx1Client) AddKICSResultsPredicates(predicates []IACResultsPredicates) error {
	c.depwarn("AddKICSResultsPredicates", "AddIACResultsPredicates")
	return c.AddIACResultsPredicates(predicates)
}
func (c *Cx1Client) AddIACResultsPredicates(predicates []IACResultsPredicates) error {
	c.config.Logger.Debugf("Adding %d IAC results predicates", len(predicates))

	jsonBody, err := json.Marshal(predicates)
	if err != nil {
		c.config.Logger.Tracef("Failed to add IAC results predicates: %s", err)
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/kics-results-predicates", bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) GetSASTResultsPredicatesByID(SimilarityID string, ProjectID, ScanID string) ([]SASTResultsPredicates, error) {
	c.config.Logger.Debugf("Fetching SAST results predicates for project %v scan %v similarityId %v", ProjectID, ScanID, SimilarityID)

	var Predicates struct {
		PredicateHistoryPerProject []struct {
			ProjectID    string
			SimilarityID string `json:"similarityId"`
			Predicates   []SASTResultsPredicates
			TotalCount   uint
		}

		TotalCount uint
	}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-results-predicates/%v?project-ids=%v&scan-id=%v", SimilarityID, ProjectID, ScanID), nil, nil)
	if err != nil {
		return []SASTResultsPredicates{}, err
	}

	err = json.Unmarshal(response, &Predicates)
	if err != nil {
		return []SASTResultsPredicates{}, err
	}

	if Predicates.TotalCount == 0 {
		return []SASTResultsPredicates{}, nil
	}

	return Predicates.PredicateHistoryPerProject[0].Predicates, err
}

func (c *Cx1Client) GetLastSASTResultsPredicateByID(SimilarityID string, ProjectID, ScanID string) (SASTResultsPredicates, error) {
	c.config.Logger.Debugf("Fetching SAST results predicates for project %v scan %v similarityId %v", ProjectID, ScanID, SimilarityID)

	var Predicates struct {
		LatestPredicatePerProject []SASTResultsPredicates `json:"latestPredicatePerProject"`
		TotalCount                uint
	}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-results-predicates/%v/latest?project-ids=%v", SimilarityID, ProjectID), nil, nil)
	if err != nil {
		return SASTResultsPredicates{}, err
	}

	err = json.Unmarshal(response, &Predicates)
	if err != nil {
		return SASTResultsPredicates{}, err
	}

	if Predicates.TotalCount == 0 {
		return SASTResultsPredicates{}, nil
	}

	return Predicates.LatestPredicatePerProject[0], err
}

func (c *Cx1Client) GetKICSResultsPredicatesByID(SimilarityID string, ProjectID string) ([]IACResultsPredicates, error) {
	c.depwarn("GetKICSResultsPredicatesByID", "GetIACResultsPredicatesByID")
	return c.GetIACResultsPredicatesByID(SimilarityID, ProjectID)
}

func (c *Cx1Client) GetIACResultsPredicatesByID(SimilarityID string, ProjectID string) ([]IACResultsPredicates, error) {
	c.config.Logger.Debugf("Fetching IAC results predicates for project %v similarityId %v", ProjectID, SimilarityID)

	var Predicates struct {
		PredicateHistoryPerProject []struct {
			ProjectID    string
			SimilarityID string `json:"similarityId"`
			Predicates   []IACResultsPredicates
			TotalCount   uint
		}

		TotalCount uint
	}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/kics-results-predicates/%v?project-ids=%v", SimilarityID, ProjectID), nil, nil)
	if err != nil {
		return []IACResultsPredicates{}, err
	}

	err = json.Unmarshal(response, &Predicates)
	if err != nil {
		return []IACResultsPredicates{}, err
	}

	if Predicates.TotalCount == 0 {
		return []IACResultsPredicates{}, nil
	}

	return Predicates.PredicateHistoryPerProject[0].Predicates, err
}

// convenience function
func (p *ResultsPredicatesBase) Update(state, severity, comment string) {
	if state != "" && state != p.State {
		p.State = state
	}
	if severity != "" && severity != p.Severity {
		p.Severity = severity
	}
	if comment != "" {
		p.Comment = comment
	}
}

func (r ScanSASTResult) String() string {
	return fmt.Sprintf("%v (%v) - %v to %v - in file %v:%d", r.Data.QueryName, r.SimilarityID, r.Data.Nodes[0].Name, r.Data.Nodes[len(r.Data.Nodes)-1].Name, r.Data.Nodes[0].FileName, r.Data.Nodes[0].Line)
}
func (r ScanIACResult) String() string {
	return fmt.Sprintf("%v - %v (%v) - %v to %v - in file %v:%d", r.Data.Group, r.Data.QueryName, r.SimilarityID, r.Data.IssueType, r.Data.Value, r.Data.FileName, r.Data.Line)
}
func (r ScanSCAResult) String() string {
	return fmt.Sprintf("%v - %v (%v) - recommended version %v: %v", r.Data.PackageIdentifier, r.Data.PublishedAt, r.SimilarityID, r.Data.RecommendedVersion, r.Data.GetType("Advisory").URL)
}
func (r ScanSCAContainerResult) String() string {
	return fmt.Sprintf("%v %v - %v (%v)", r.Data.PackageName, r.Data.PackageVersion, r.Data.PublishedAt, r.SimilarityID)
}
func (r ScanContainersResult) String() string {
	return fmt.Sprintf("%v %v / %v #%v (%v)", r.Data.PackageName, r.Data.PackageVersion, r.Data.ImageName, r.Data.ImageTag, r.SimilarityID)
}

func (r ScanSCAResultData) GetType(packageDataType string) ScanSCAResultPackageData {
	for _, p := range r.PackageData {
		if strings.EqualFold(p.Type, packageDataType) {
			return p
		}
	}
	return ScanSCAResultPackageData{}
}

func addResultStatus(summary *ScanResultStatusSummary, result *ScanSASTResult) {
	switch result.State {
	case "CONFIRMED":
		summary.Confirmed++
	case "URGENT":
		summary.Urgent++
	case "URGENT ":
		summary.Urgent++
	case "PROPOSED_NOT_EXPLOITABLE":
		summary.ProposedNotExploitable++
	case "NOT_EXPLOITABLE":
		summary.NotExploitable++
	default:
		summary.ToVerify++
	}
}

func (c *Cx1Client) GetScanSASTResultSummary(results *ScanResultSet) ScanResultSummary {
	summary := ScanResultSummary{}

	for _, result := range results.SAST {
		switch result.Severity {
		case "HIGH":
			addResultStatus(&(summary.High), &result)
		case "MEDIUM":
			addResultStatus(&(summary.Medium), &result)
		case "LOW":
			addResultStatus(&(summary.Low), &result)
		default:
			addResultStatus(&(summary.Information), &result)
		}
	}

	return summary
}

func (s ScanResultSet) String() string {
	return fmt.Sprintf("Result set with %d SAST, %d SCA, %d SCAContainer, %d IAC, and %d Containers results", len(s.SAST), len(s.SCA), len(s.SCAContainer), len(s.IAC), len(s.Containers))
}

func (s ScanResultSet) Count() uint64 {
	return uint64(len(s.SAST) + len(s.SCA) + len(s.SCAContainer) + len(s.IAC) + len(s.Containers))
}

func (s *ScanResultSet) Append(results *ScanResultSet) {
	if len(results.IAC) > 0 {
		s.IAC = append(s.IAC, results.IAC...)
	}
	if len(results.SCA) > 0 {
		s.SCA = append(s.SCA, results.SCA...)
	}
	if len(results.SCAContainer) > 0 {
		s.SCAContainer = append(s.SCAContainer, results.SCAContainer...)
	}
	if len(results.SAST) > 0 {
		s.SAST = append(s.SAST, results.SAST...)
	}
	if len(results.Containers) > 0 {
		s.Containers = append(s.Containers, results.Containers...)
	}
}

func (s ScanResultStatusSummary) Total() uint64 {
	return s.ToVerify + s.Confirmed + s.Urgent + s.ProposedNotExploitable + s.NotExploitable
}
func (s ScanResultStatusSummary) String() string {
	return fmt.Sprintf("To Verify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d", s.ToVerify, s.Confirmed, s.Urgent, s.ProposedNotExploitable, s.NotExploitable)
}
func (s ScanResultSummary) String() string {
	return fmt.Sprintf("%v\n%v\n%v", fmt.Sprintf("\tHigh: %v\n\tMedium: %v\n\tLow: %v\n\tInfo: %v", s.High.String(), s.Medium.String(), s.Low.String(), s.Information.String()),
		fmt.Sprintf("\tTotal High: %d, Medium: %d, Low: %d, Info: %d", s.High.Total(), s.Medium.Total(), s.Low.Total(), s.Information.Total()),
		fmt.Sprintf("\tTotal ToVerify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d",
			s.High.ToVerify+s.Medium.ToVerify+s.Low.ToVerify+s.Information.ToVerify,
			s.High.Confirmed+s.Medium.Confirmed+s.Low.Confirmed+s.Information.Confirmed,
			s.High.Urgent+s.Medium.Urgent+s.Low.Urgent+s.Information.Urgent,
			s.High.ProposedNotExploitable+s.Medium.ProposedNotExploitable+s.Low.ProposedNotExploitable+s.Information.ProposedNotExploitable,
			s.High.NotExploitable+s.Medium.NotExploitable+s.Low.NotExploitable+s.Information.NotExploitable))
}

// Note: response.TotalCount may be greater than the resultset, due to limited cx1clientgo engine support
func (c *Cx1Client) parseScanResults(scanId string, response []byte) (uint64, ScanResultSet, error) {
	var resultResponse struct {
		Results    []map[string]interface{}
		TotalCount uint64
	}

	var ResultSet ScanResultSet

	scan, err := c.GetScanByID(scanId)
	if err != nil {
		return 0, ResultSet, err
	}

	dec := json.NewDecoder(bytes.NewReader(response))
	dec.UseNumber()
	err = dec.Decode(&resultResponse)
	if err != nil {
		c.config.Logger.Tracef("Failed while parsing response: %s", err)
		//c.config.Logger.Tracef("Response contents: %s", string(response))
		return resultResponse.TotalCount, ResultSet, err
	}
	//c.config.Logger.Debugf("Retrieved %d results", resultResponse.TotalCount)

	/*
		if uint64(len(resultResponse.Results)) != resultResponse.TotalCount {
			c.config.Logger.Warnf("Expected results total count %d but parsed only %d", resultResponse.TotalCount, len(resultResponse.Results))
			c.config.Logger.Tracef("Response was: %v", string(response))
		}
	*/

	for _, r := range resultResponse.Results {
		//c.config.Logger.Infof("Result %v: %v", r["similarityId"].(string), r["type"].(string))
		jsonResult, _ := json.Marshal(r)
		switch r["type"].(string) {
		case "sast":
			var SASTResult ScanSASTResult
			err := json.Unmarshal(jsonResult, &SASTResult)
			if err != nil {
				c.config.Logger.Warnf("Failed to unmarshal result %v to SAST type: %s", r["similarityId"].(string), err)
			} else {
				if SASTResult.ScanID == "" {
					SASTResult.ScanID = scanId
				}
				if SASTResult.ProjectID == "" {
					SASTResult.ProjectID = scan.ProjectID
				}
				ResultSet.SAST = append(ResultSet.SAST, SASTResult)
			}
		case "sca":
			var SCAResult ScanSCAResult
			err := json.Unmarshal(jsonResult, &SCAResult)
			if err != nil {
				c.config.Logger.Warnf("Failed to unmarshal result %v to SCA type: %s", r["similarityId"].(string), err)
			} else {
				if SCAResult.ScanID == "" {
					SCAResult.ScanID = scanId
				}
				if SCAResult.ProjectID == "" {
					SCAResult.ProjectID = scan.ProjectID
				}
				ResultSet.SCA = append(ResultSet.SCA, SCAResult)
			}
		case "kics":
			var IACResult ScanIACResult
			err := json.Unmarshal(jsonResult, &IACResult)
			if err != nil {
				c.config.Logger.Warnf("Failed to unmarshal result %v to IAC type: %s", r["similarityId"].(string), err)
			} else {
				if IACResult.ScanID == "" {
					IACResult.ScanID = scanId
				}
				if IACResult.ProjectID == "" {
					IACResult.ProjectID = scan.ProjectID
				}
				ResultSet.IAC = append(ResultSet.IAC, IACResult)
			}
		case "sca-container":
			var SCACResult ScanSCAContainerResult
			err := json.Unmarshal(jsonResult, &SCACResult)
			if err != nil {
				c.config.Logger.Warnf("Failed to unmarshal result %v to SCAContainer type: %s", r["similarityId"].(string), err)
			} else {
				if SCACResult.ScanID == "" {
					SCACResult.ScanID = scanId
				}
				if SCACResult.ProjectID == "" {
					SCACResult.ProjectID = scan.ProjectID
				}
				ResultSet.SCAContainer = append(ResultSet.SCAContainer, SCACResult)
			}
		case "containers":
			var ContainerResult ScanContainersResult
			err := json.Unmarshal(jsonResult, &ContainerResult)
			if err != nil {
				c.config.Logger.Warnf("Failed to unmarshal result %v to Containers type: %s", r["similarityId"].(string), err)
			} else {
				if ContainerResult.ScanID == "" {
					ContainerResult.ScanID = scanId
				}
				if ContainerResult.ProjectID == "" {
					ContainerResult.ProjectID = scan.ProjectID
				}
				ResultSet.Containers = append(ResultSet.Containers, ContainerResult)
			}
		default:
			c.config.Logger.Warnf("Unable to unmarshal result %v of unknown type %v", r["similarityId"].(string), r["type"].(string))
		}
	}

	c.config.Logger.Debugf("Retrieved %d of %d results", ResultSet.Count(), resultResponse.TotalCount)

	return resultResponse.TotalCount, ResultSet, nil
}

func (b ResultsPredicatesBase) String() string {
	return fmt.Sprintf("[%v] %v set severity %v, state %v, comment %v", b.CreatedAt, b.CreatedBy, b.Severity, b.State, b.Comment)
}

func (c *Cx1Client) GetCustomResultStates() ([]ResultState, error) {
	states := []ResultState{}
	response, err := c.sendRequest(http.MethodGet, "/custom-states", nil, nil)
	if err != nil {
		return states, err
	}

	err = json.Unmarshal(response, &states)
	return states, err
}

func (c *Cx1Client) CreateCustomResultState(state string) (ResultState, error) {
	var resultstate ResultState

	var requestBody struct {
		Name string `json:"name"`
	}
	requestBody.Name = state

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return resultstate, err
	}

	response, err := c.sendRequest(http.MethodPost, "/custom-states", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return resultstate, err
	}

	err = json.Unmarshal(response, &resultstate)
	resultstate.IsAllowed = true
	return resultstate, err
}

func (c *Cx1Client) DeleteCustomResultState(stateId uint64) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/custom-states/%d", stateId), nil, nil)
	return err
}

func (c ResultState) String() string {
	return fmt.Sprintf("[%d] %v", c.ID, c.Name)
}

// returns the full history of results changes for a specific project
func (c *Cx1Client) GetResultsChangeHistoryForProjectByID(projectID string) ([]ResultsChangeHistory, error) {
	_, changes, err := c.GetAllResultsChangeHistoryFiltered(ResultsChangeFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Results},
		History:    true,
		EntityID:   projectID,
		EntityType: "projectID",
	})

	return changes, err
}

// returns the full history of results changes for a specific scan
func (c *Cx1Client) GetResultsChangeHistoryForScanByID(scanID string) ([]ResultsChangeHistory, error) {
	_, changes, err := c.GetAllResultsChangeHistoryFiltered(ResultsChangeFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Results},
		History:    true,
		EntityID:   scanID,
		EntityType: "scanID",
	})

	return changes, err
}

// returns the full history of results changes for a specific similarityID
func (c *Cx1Client) GetResultsChangeHistoryForSimilarityID(similarityID string) ([]ResultsChangeHistory, error) {
	_, changes, err := c.GetAllResultsChangeHistoryFiltered(ResultsChangeFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Results},
		History:    true,
		EntityID:   similarityID,
		EntityType: "similarityID",
	})

	return changes, err
}

// results bulk retrieval - Changelog
func (c *Cx1Client) GetResultsChangeHistoryFiltered(filter ResultsChangeFilter) (uint64, []ResultsChangeHistory, error) {
	params, _ := query.Values(filter)

	var response struct {
		Results            []ResultsChangeHistory `json:"results"`
		TotalSimilarityIds string                 `json:"totalSimilarityIds"`
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-results-predicates/changelog?%v", params.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch scans matching filter %v: %s", params.Encode(), err)
		c.config.Logger.Tracef("Error: %s", err)
		return 0, response.Results, err
	}

	err = json.Unmarshal(data, &response)
	if err != nil {
		return 0, response.Results, err
	}

	// response.TotalSimilarityIds contains something like: "presenting 10 of 29"
	var count, total uint64
	if filter.EntityType == "similarityID" {
		count = 1
		total = 1
	} else {
		_, err = fmt.Sscanf(response.TotalSimilarityIds, "presenting %d of %d", &count, &total)
		if err != nil {
			// If parsing fails, we might not have the total, but we can return what we have.
			// The API might change its format.
			c.config.Logger.Warnf("Could not parse TotalSimilarityIds string: '%s'", response.TotalSimilarityIds)
		}
	}

	return total, response.Results, nil
}

// gets all of the results changes available matching a filter
func (c *Cx1Client) GetAllResultsChangeHistoryFiltered(filter ResultsChangeFilter) (uint64, []ResultsChangeHistory, error) {
	var results []ResultsChangeHistory

	count, rs, err := c.GetResultsChangeHistoryFiltered(filter)
	results = rs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, rs, err = c.GetResultsChangeHistoryFiltered(filter)
		results = append(results, rs...)
	}

	return uint64(len(results)), results, err
}

// will return at least X resultschanges matching the filter
// May return more due to paging eg: requesting 101 with a 100-item page can return 200 results
func (c *Cx1Client) GetXResultsChangeHistoryFiltered(filter ResultsChangeFilter, desiredcount uint64) (uint64, []ResultsChangeHistory, error) {
	var results []ResultsChangeHistory

	_, rs, err := c.GetResultsChangeHistoryFiltered(filter)
	results = rs

	for err == nil && desiredcount > filter.Offset+filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, rs, err = c.GetResultsChangeHistoryFiltered(filter)
		results = append(results, rs...)
	}

	if len(results) > int(desiredcount) {
		results = results[:desiredcount]
	}

	return uint64(len(results)), results, err
}
