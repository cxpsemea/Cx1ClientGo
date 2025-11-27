package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

func (c *Cx1Client) GetScanSASTResultsByID(scanID string, limit uint64) ([]ScanSASTResult, error) {
	c.logger.Debugf("Get %d Cx1 Scan Results for scan %v", limit, scanID)

	_, results, err := c.GetXScanSASTResultsFiltered(ScanSASTResultsFilter{
		BaseFilter:      BaseFilter{Limit: c.pagination.Results},
		ScanID:          scanID,
		IncludeNodes:    boolPtr(true),
		ApplyPredicates: boolPtr(true),
		Sort:            []string{"+similarity-id", "+result-id"},
	}, limit)

	return results, err
}

func (c *Cx1Client) GetAllScanSASTResultsByID(scanID string) ([]ScanSASTResult, error) {
	c.logger.Debugf("Get all Cx1 Scan Results for scan %v", scanID)

	_, results, err := c.GetAllScanSASTResultsFiltered(ScanSASTResultsFilter{
		BaseFilter:      BaseFilter{Limit: c.pagination.Results},
		ScanID:          scanID,
		IncludeNodes:    boolPtr(true),
		ApplyPredicates: boolPtr(true),
		Sort:            []string{"+similarity-id", "+result-id"},
	})

	return results, err
}

func (c *Cx1Client) GetScanSASTResultsCountByID(scanID string) (uint64, error) {
	c.logger.Debugf("Get Cx1 Scan Results count for scan %v", scanID)
	count, _, err := c.GetScanSASTResultsFiltered(ScanSASTResultsFilter{
		BaseFilter:      BaseFilter{Limit: 0},
		ScanID:          scanID,
		IncludeNodes:    boolPtr(false),
		ApplyPredicates: boolPtr(false),
	})

	return count, err
}

// returns one 'page' of a scan's SAST results matching the filter
// returns items (filter.Offset*filter.Limit) to (filter.Offset + 1)*filter.Limit
func (c *Cx1Client) GetScanSASTResultsFiltered(filter ScanSASTResultsFilter) (uint64, []ScanSASTResult, error) {
	params, _ := query.Values(filter)

	// this API returns a slightly different format result, with some fields that appear empty and are skipped in this struct
	type SASTResult struct {
		CweID           int
		Compliances     []string
		ConfidenceLevel int
		FirstFoundAt    string
		FoundAt         string
		FirstScanId     string
		Group           string
		Language        string `json:"languageName"`
		Nodes           []ScanSASTResultNodes
		QueryID         uint64
		QueryIDStr      string
		QueryName       string
		ResultHash      string
		Severity        string
		SimilarityID    int64
		State           string
		Status          string
		CVSSScore       float64
		ProjectID       string
		ScanID          string
		SourceFileName  string
	}

	var results []ScanSASTResult
	var temp_results struct {
		Results    []SASTResult
		TotalCount uint64
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-results/?%v", params.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch scans matching filter %v: %s", params.Encode(), err)
		c.logger.Tracef("Error: %s", err)
		return 0, results, err
	}

	err = json.Unmarshal(data, &temp_results)
	if err != nil {
		return 0, results, err
	}

	for _, r := range temp_results.Results {
		results = append(results, ScanSASTResult{
			ScanResultBase: ScanResultBase{
				Type:            "sast",
				ResultID:        r.ResultHash,
				SimilarityID:    fmt.Sprintf("%d", r.SimilarityID),
				Status:          r.Status,
				State:           r.State,
				Severity:        r.Severity,
				ConfidenceLevel: r.ConfidenceLevel,
				CreatedAt:       r.FirstFoundAt,
				FirstFoundAt:    r.FirstFoundAt,
				FoundAt:         r.FoundAt,
				FirstScanId:     r.FirstScanId,
				Description:     "",
				CVSSScore:       r.CVSSScore,
				ProjectID:       r.ProjectID,
				ScanID:          r.ScanID,
				SourceFileName:  r.SourceFileName,
			},
			Data: ScanSASTResultData{
				QueryID:      r.QueryID,
				QueryName:    r.QueryName,
				Group:        r.Group,
				ResultHash:   r.ResultHash,
				LanguageName: r.Language,
				Nodes:        r.Nodes,
			},
			VulnerabilityDetails: ScanSASTResultDetails{
				CweId:       r.CweID,
				Compliances: r.Compliances,
			},
		})
	}

	//count, results, err := c.parseScanSASTResults(data)
	return temp_results.TotalCount, results, err
}

func (s *ScanSASTResultsFilter) Bump() { // this one does offset in items
	s.Offset += s.Limit
}

// gets all of the results available matching a filter
// the counter returned represents the total number of results which were parsed
// this may not include some of the returned results depending on Cx1ClientGo support
func (c *Cx1Client) GetAllScanSASTResultsFiltered(filter ScanSASTResultsFilter) (uint64, []ScanSASTResult, error) {

	var results []ScanSASTResult

	countFilter := filter
	countFilter.Limit = 1
	count, _, err := c.GetScanSASTResultsFiltered(countFilter)
	if err != nil {
		return 0, results, err
	}
	_, results, err = c.GetXScanSASTResultsFiltered(filter, count)

	return uint64(len(results)), results, err
}

// will return at least X results matching the filter
// May return more due to paging eg: requesting 101 with a 100-item page can return 200 results
func (c *Cx1Client) GetXScanSASTResultsFiltered(filter ScanSASTResultsFilter, desiredcount uint64) (uint64, []ScanSASTResult, error) {
	var results []ScanSASTResult

	_, rs, err := c.GetScanSASTResultsFiltered(filter)
	results = rs

	for err == nil && desiredcount > filter.Offset+filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, rs, err = c.GetScanSASTResultsFiltered(filter)
		results = append(results, rs...)
	}

	if uint64(len(results)) > desiredcount {
		results = results[:desiredcount]
	}

	return uint64(len(results)), results, err
}
