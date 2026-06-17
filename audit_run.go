package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Cx1Client) validateQuerySourceByKey(auditSession *AuditSession, queryKey, source string) ([]QueryRunFailure, error) {
	c.config.Logger.Debugf("Validating query source by key: %v", queryKey)
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	var queryFail []QueryRunFailure
	postbody := make([]QueryUpdate, 1)
	postbody[0].ID = queryKey
	postbody[0].Source = source

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries/validate", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return queryFail, fmt.Errorf("failed to send source: %s", err)
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	responseObj, err := c.auditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return queryFail, fmt.Errorf("failed due to %s: %v", err, responseObj)
	}

	if responseMap, ok := responseObj.(map[string]interface{}); ok {
		if val, ok := responseMap["failed_queries"]; ok {
			bytes, _ := json.Marshal(val)
			err = json.Unmarshal(bytes, &queryFail)
			if err != nil {
				return queryFail, fmt.Errorf("failed to unmarshal failure: %s", err)
			}

			if len(queryFail) == 0 {
				return queryFail, nil
			} else {
				return queryFail, fmt.Errorf("failed to validate source")
			}
		}
	}
	return queryFail, nil
}

func (c *Cx1Client) ValidateSASTQuerySource(auditSession *AuditSession, query *SASTQuery, source string) ([]QueryRunFailure, error) {
	if query.EditorKey == "" {
		return []QueryRunFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.validateQuerySourceByKey(auditSession, query.EditorKey, source)
}

func (c *Cx1Client) ValidateIACQuerySource(auditSession *AuditSession, query *IACQuery, source string) ([]QueryRunFailure, error) {
	if query.Key == "" {
		return []QueryRunFailure{}, fmt.Errorf("query %v does not have an Key, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.validateQuerySourceByKey(auditSession, query.Key, source)
}

func (c *Cx1Client) runQueryByKey(auditSession *AuditSession, queryKey, source string) (QueryRun, error) {
	c.config.Logger.Debugf("Running query by key: %v", queryKey)
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	postbody := make([]QueryUpdate, 1)
	postbody[0].ID = queryKey
	postbody[0].Source = source

	var qr QueryRun

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return qr, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries/run", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return qr, fmt.Errorf("failed to run: %s", err)
	}

	var auditRequest requestIDBody
	err = json.Unmarshal(response, &auditRequest)
	if err != nil {
		return qr, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	value, err := c.auditRequestStatusPollingByID(auditSession, auditRequest.Id)
	if err != nil {
		return qr, fmt.Errorf("failed due to %s: %v", err, value)
	}

	return parseQueryRun(auditRequest.Id, value)
}

func parseQueryRun(auditRequestId string, value interface{}) (QueryRun, error) {
	var qr QueryRun

	// response object will have "value":{ "failed_queries":[] } if there are errors
	if responseMap, ok := value.(map[string]interface{}); ok {
		if val, ok := responseMap["failed_queries"]; ok {
			bytes, _ := json.Marshal(val)
			err := json.Unmarshal(bytes, &qr.FailedQueries)
			if err != nil {
				return qr, fmt.Errorf("failed to unmarshal failures: %s", err)
			}
			if len(qr.FailedQueries) == 0 {
				return qr, fmt.Errorf("empty failed_queries in response: %+v", responseMap)
			}
			return qr, nil
		} else {
			return qr, fmt.Errorf("missing failed_queries in response: %+v", responseMap)
		}
	} else {
		bytes, _ := json.Marshal(value)
		var tree []AuditQueryTree
		err := json.Unmarshal(bytes, &tree)
		if err != nil {
			return qr, fmt.Errorf("failed to unmarshal results: %s", err)
		}

		for _, lang := range tree {
			for _, query := range lang.Children {
				qr.Results = append(qr.Results, QueryRunResult{
					RequestID: auditRequestId,
					RunID:     query.Key,
					Language:  lang.Title,
					Title:     query.Title,
				})
			}
		}

		if len(qr.Results) == 0 {
			return qr, fmt.Errorf("empty results in response: %+v", tree)
		}
		return qr, nil
	}
}

/*
This will test if the code compiles and will not update the source code in Cx1 nor in the query object
Cx1ClientGo does not yet expose a method to retrieve the results of an audit query execution - this is effectively the same as Validate*QuerySource
*/
func (c *Cx1Client) RunSASTQuery(auditSession *AuditSession, query *SASTQuery, source string) (QueryRun, error) {
	if query.EditorKey == "" {
		return QueryRun{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.runQueryByKey(auditSession, query.EditorKey, source)
}

/*
This will test if the code compiles and will not update the source code in Cx1 nor in the query object
Cx1ClientGo does not yet expose a method to retrieve the results of an audit query execution - this is effectively the same as Validate*QuerySource
*/
func (c *Cx1Client) RunIACQuery(auditSession *AuditSession, query *IACQuery, source string) (QueryRun, error) {
	if query.Key == "" {
		return QueryRun{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.runQueryByKey(auditSession, query.Key, source)
}

// Get the results for an Audit session query-run. This is a list of vulnerabilities found by the query run.
func (c *Cx1Client) GetQueryRunResultsByID(auditSession *AuditSession, runId string) ([]QueryVulnerabilityShort, error) {
	var response struct {
		Data []QueryVulnerabilityShort `json:"data"`
	}

	responseBytes, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/results/%v/vulnerabilities?pageSize=10&currentPage=1", auditSession.ID, runId), nil, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(responseBytes, &response)
	return response.Data, err
}

// Get the details of a vulnerability found during an audit session query run.
func (c *Cx1Client) GetQueryRunVulnerabilityByID(auditSession *AuditSession, runId, vulnerabilityId string) (QueryVulnerability, error) {
	var vuln QueryVulnerability

	responseBytes, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/results/%v/vulnerabilities/%v", auditSession.ID, runId, vulnerabilityId), nil, nil)
	if err != nil {
		return vuln, err
	}

	err = json.Unmarshal(responseBytes, &vuln)
	return vuln, err
}
