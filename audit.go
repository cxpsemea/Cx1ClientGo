package Cx1ClientGo

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/*
	This is separate from queries.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the query-related functions that require an audit session (compiling queries, updating queries, creating overrides)
*/

var AUDIT_QUERY = struct {
	PRODUCT     string
	TENANT      string
	APPLICATION string
	PROJECT     string
}{"Cx", "Tenant", "Application", "Project"}

type requestIDBody struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Id      string `json:"id"`
}

type newIACQuery struct {
	IACQuery
	ID          string `json:"id"`
	QueryName   string `json:"queryname"`
	OldSeverity string `json:"oldseverity"`
}

/*
type requestQueryStatus struct {
	AlreadyExists bool   `json:"alreadyExists"`
	EditorKey     string `json:"id"`
}
*/

func (c Cx1Client) QueryTypeProduct() string {
	return AUDIT_QUERY.PRODUCT
}
func (c Cx1Client) QueryTypeTenant() string {
	return AUDIT_QUERY.TENANT
}
func (c Cx1Client) QueryTypeApplication() string {
	return AUDIT_QUERY.APPLICATION
}
func (c Cx1Client) QueryTypeProject() string {
	return AUDIT_QUERY.PROJECT
}

func (c Cx1Client) AuditCreateSession(engine, filter string) (AuditSession, error) {
	c.logger.Debugf("Trying to create a tenant-level audit session for engine %v and filter %v", engine, filter)

	body := map[string]string{
		"scanner": engine,
		"filter":  filter,
	}
	jsonBody, _ := json.Marshal(body)

	var session AuditSession

	response, err := c.sendRequest(http.MethodPost, "/query-editor/sessions", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return session, err
	}

	err = json.Unmarshal(response, &session)
	if err != nil {
		return session, err
	}
	session.CreatedAt = time.Now()
	session.LastHeartbeat = time.Now()
	session.Engine = engine

	if session.Data.Status != "ALLOCATED" {
		return session, fmt.Errorf("failed to allocate audit session: %v", session.Data.Status)
	}

	languageResponse, err := c.AuditRequestStatusPollingByID(&session, session.Data.RequestID)

	if err != nil {
		c.logger.Errorf("Error while creating audit engine: %s", err)
		return session, err
	}
	if languages, ok := languageResponse.([]interface{}); ok {
		for _, lang := range languages {
			session.Languages = append(session.Languages, lang.(string))
		}

	} else {
		return session, fmt.Errorf("failed to get languages from response: %v", languageResponse)
	}

	session.ProjectID = ""
	session.ApplicationID = ""

	c.logger.Debugf("Created audit session %v under tenant with engine %v and filter %v", session.ID, engine, filter)

	return session, nil

}

func (c Cx1Client) AuditCreateSessionByID(engine, projectId, scanId string) (AuditSession, error) {
	engine = strings.ToLower(engine)
	c.logger.Debugf("Trying to create %v audit session for project %v scan %v", engine, projectId, scanId)
	/*available, _, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		return "", err
	}

	if !available {
		return "", fmt.Errorf("audit session not available")
	}*/

	var session AuditSession
	var appId string

	if engine != "sast" && engine != "iac" {
		return session, fmt.Errorf("unknown engine %v", engine)
	}

	proj, err := c.GetProjectByID(projectId)
	if err != nil {
		c.logger.Errorf("Unknown project %v", projectId)
	} else {
		if len(*proj.Applications) == 1 {
			appId = (*proj.Applications)[0]
		} else if len(*proj.Applications) > 1 {
			appId = "Error: multiple owning applications"
		}
	}

	body := map[string]interface{}{
		"projectId": projectId,
		"scanId":    scanId,
		"scanner":   engine,
	}

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequest(http.MethodPost, "/query-editor/sessions", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return session, err
	}

	err = json.Unmarshal(response, &session)
	if err != nil {
		return session, err
	}
	session.Engine = engine

	if engine == "sast" {
		if session.Data.Status != "ALLOCATED" {
			return session, fmt.Errorf("failed to allocate audit session: %v", session.Data.Status)
		}

		languageResponse, err := c.AuditRequestStatusPollingByID(&session, session.Data.RequestID)

		if err != nil {
			c.logger.Errorf("Error while creating audit engine: %s", err)
			return session, err
		}
		if languages, ok := languageResponse.([]interface{}); ok {
			for _, lang := range languages {
				session.Languages = append(session.Languages, lang.(string))
			}

		} else {
			return session, fmt.Errorf("failed to get languages from response: %v", languageResponse)
		}
	} else if engine == "iac" {
		if session.Data.Status != "RUNNING" {
			return session, fmt.Errorf("failed to start audit session: %v", session.Data.Status)
		}
		session.Platforms = session.Data.QueryFilters
	}

	session.ProjectID = projectId
	session.ApplicationID = appId
	session.CreatedAt = time.Now()
	session.LastHeartbeat = time.Now()

	c.logger.Debugf("Created audit session %v under project %v, app %v", session.ID, session.ProjectID, session.ApplicationID)

	return session, nil
}

func (c Cx1Client) AuditDeleteSession(auditSession *AuditSession) error {
	if auditSession == nil {
		c.logger.Errorf("Attempt to run AuditDeleteSession with a nil session")
		return nil
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v", auditSession.ID), nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) AuditGetRequestStatusByID(auditSession *AuditSession, requestId string) (bool, interface{}, error) {
	c.logger.Debugf("Get status of request %v for %v", requestId, auditSession.String())
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/requests/%v", auditSession.ID, requestId), nil, nil)
	type AuditRequestStatus struct {
		Completed    bool        `json:"completed"`
		Value        interface{} `json:"value"`
		ErrorCode    int         `json:"code"`
		ErrorMessage string      `json:"message"`
		Status       string      `json:"status"`
	}

	var status AuditRequestStatus
	if err != nil {
		return false, status.Value, err
	}

	err = json.Unmarshal(response, &status)
	if err != nil {
		return false, status.Value, err
	}

	if status.ErrorCode != 0 && status.ErrorMessage != "" {
		return false, status.Value, fmt.Errorf("query editor returned error code %d: %v", status.ErrorCode, status.ErrorMessage)
	}

	if status.Status == "Failed" {
		return false, status.Value, fmt.Errorf("query editor returned error: %v", status.Value)
	}

	return status.Completed, status.Value, nil
}

func (c Cx1Client) AuditRequestStatusPollingByID(auditSession *AuditSession, requestId string) (interface{}, error) {
	return c.AuditRequestStatusPollingByIDWithTimeout(auditSession, requestId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditRequestStatusPollingByIDWithTimeout(auditSession *AuditSession, requestId string, delaySeconds, maxSeconds int) (interface{}, error) {
	c.logger.Debugf("Polling status of request %v for %v", requestId, auditSession.String())
	var value interface{}
	var err error
	var status bool
	pollingCounter := 0

	for {
		status, value, err = c.AuditGetRequestStatusByID(auditSession, requestId)
		if err != nil {
			return value, err
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return value, fmt.Errorf("audit request %v polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", requestId, pollingCounter)
		}

		if status {
			break
		}

		// TODO: also refresh the audit session
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return value, nil
}

func (c Cx1Client) AuditSessionKeepAlive(auditSession *AuditSession) error {
	if time.Since(auditSession.LastHeartbeat) < 5*time.Minute {
		c.logger.Tracef("Audit session last refreshed within 5 minutes ago, skipping")
		return nil
	}
	_, err := c.sendRequest(http.MethodPatch, fmt.Sprintf("/query-editor/sessions/%v", auditSession.ID), nil, nil)
	if err != nil {
		return err
	}
	auditSession.LastHeartbeat = time.Now()
	return nil
}

// Convenience function
func (c Cx1Client) GetAuditSessionByID(engine, projectId, scanId string) (AuditSession, error) {
	// TODO: convert the audit session to an object that also does the polling/keepalive
	c.logger.Infof("Creating an audit session for project %v scan %v", projectId, scanId)

	session, err := c.AuditCreateSessionByID(engine, projectId, scanId)
	if err != nil {
		c.logger.Errorf("Error creating cxaudit session: %s", err)
		return session, err
	}
	//}

	err = c.AuditSessionKeepAlive(&session)
	if err != nil {
		return session, err
	}

	//c.logger.Infof("Languages present: %v", status.Value.([]string))

	_, err = c.AuditGetScanSourcesByID(&session)
	if err != nil {
		return session, fmt.Errorf("error while getting scan sources: %v", session.ID)
	}

	err = c.AuditRunScanByID(&session)
	if err != nil {
		c.logger.Errorf("Error while triggering audit scan: %s", err)
		return session, err
	}

	c.AuditSessionKeepAlive(&session) // one for the road
	return session, nil
}

func (c Cx1Client) AuditGetScanSourcesByID(auditSession *AuditSession) ([]AuditScanSourceFile, error) {
	c.logger.Debugf("Get %v scan sources", auditSession.String())

	var sourcefiles []AuditScanSourceFile

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/sources", auditSession.ID), nil, nil)
	if err != nil {
		return sourcefiles, err
	}

	err = json.Unmarshal(response, &sourcefiles)
	return sourcefiles, err
}

func (c Cx1Client) AuditRunScanByID(auditSession *AuditSession) error {
	c.logger.Infof("Triggering scan under %v", auditSession.String())
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/sources/scan", auditSession.ID), nil, nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody

	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return err
	}

	if responseBody.Code != 0 && responseBody.Message != "" {
		return fmt.Errorf("audit scan returned error %d: %v", responseBody.Code, responseBody.Message)
	}

	_, err = c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		c.logger.Errorf("Error while polling audit scan: %s", err)
		return err
	}

	return nil
}

func (q AuditSASTQuery) String() string {
	return fmt.Sprintf("[%v] %v: %v", ShortenGUID(q.Key), q.Level, q.Path)
}

func (c Cx1Client) GetAuditQueryByKey(auditSession *AuditSession, key string) (SASTQuery, error) {
	c.depwarn("GetAuditQueryByKey", "GetAuditSASTQueryByKey")
	return c.GetAuditSASTQueryByKey(auditSession, key)
}
func (c Cx1Client) GetAuditSASTQueryByKey(auditSession *AuditSession, key string) (SASTQuery, error) {
	c.logger.Debugf("Get audit query by key: %v", key)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", auditSession.ID, url.QueryEscape(key)), nil, nil)
	if err != nil {
		return SASTQuery{}, err
	}

	var q AuditSASTQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return SASTQuery{}, err
	}

	query := q.ToSASTQuery()
	switch query.Level {
	case AUDIT_QUERY.APPLICATION:
		query.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY.PRODUCT:
		query.LevelID = AUDIT_QUERY.PRODUCT
	case AUDIT_QUERY.PROJECT:
		query.LevelID = auditSession.ProjectID
	case AUDIT_QUERY.TENANT:
		query.LevelID = AUDIT_QUERY.TENANT
	}

	return query, nil
}

func (c Cx1Client) GetAuditIACQueryByID(auditSession *AuditSession, queryId string) (IACQuery, error) {
	c.logger.Debugf("Get audit IAC query by ID: %v", queryId)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v?includeMetadata=true&includeSource=true", auditSession.ID, url.QueryEscape(queryId)), nil, nil)
	if err != nil {
		return IACQuery{}, err
	}

	var q AuditIACQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return IACQuery{}, err
	}
	if q.QueryID[1] == ':' {
		q.Key = q.QueryID[2:]
	} else {
		q.Key = q.QueryID
	}

	query := q.ToIACQuery()
	switch query.Level {
	case AUDIT_QUERY.APPLICATION:
		query.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY.PRODUCT:
		query.LevelID = AUDIT_QUERY.PRODUCT
	case AUDIT_QUERY.PROJECT:
		query.LevelID = auditSession.ProjectID
	case AUDIT_QUERY.TENANT:
		query.LevelID = AUDIT_QUERY.TENANT
	}

	return query, nil
}

/*
Retrieves the list of queries available for this audit session. Level and LevelID options are:
QueryTypeProduct(), QueryTypeProduct() : same value for both when retrieving product-level queries
QueryTypeTenant(), QueryTypeTenant() : same value for both when retrieving tenant-level queries
QueryTypeApplication(), application.ApplicationID : when retrieving application-level queries
QueryTypeProject(), project.ProjectID : when retrieving project-level queries

The resulting array of queries should be merged into a QueryCollection object returned by the GetQueries function.
*/
func (c Cx1Client) GetAuditQueriesByLevelID(auditSession *AuditSession, level, levelId string) (SASTQueryCollection, error) {
	c.depwarn("GetAuditQueriesByLevelID", "GetAuditSASTQueriesByLevelID")
	return c.GetAuditSASTQueriesByLevelID(auditSession, level, levelId)
}
func (c Cx1Client) GetAuditSASTQueriesByLevelID(auditSession *AuditSession, level, levelId string) (SASTQueryCollection, error) {
	c.logger.Debugf("Get all queries for %v %v", level, levelId)

	collection := SASTQueryCollection{}
	querytree, err := c.GetAuditQueryTreeByLevelID(auditSession, level, levelId)
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&querytree, auditSession.ApplicationID, levelId, false)

	return collection, nil
}
func (c Cx1Client) GetAuditIACQueriesByLevelID(auditSession *AuditSession, level, levelId string) (IACQueryCollection, error) {
	c.logger.Debugf("Get all queries for %v %v", level, levelId)

	collection := IACQueryCollection{}
	querytree, err := c.GetAuditQueryTreeByLevelID(auditSession, level, levelId)
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&querytree, auditSession.ApplicationID, levelId)

	return collection, nil
}
func (c Cx1Client) GetAuditQueryTreeByLevelID(auditSession *AuditSession, level, levelId string) ([]AuditQueryTree, error) {
	var url string
	var querytree []AuditQueryTree
	switch level {
	case AUDIT_QUERY.TENANT:
		url = fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID)
	case AUDIT_QUERY.PROJECT:
		url = fmt.Sprintf("/query-editor/sessions/%v/queries?projectId=%v", auditSession.ID, levelId)
	default:
		return querytree, fmt.Errorf("invalid level %v, options are currently: %v or %v", level, AUDIT_QUERY.TENANT, AUDIT_QUERY.PROJECT)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return querytree, err
	}

	err = json.Unmarshal(response, &querytree)
	return querytree, err
}

func (c Cx1Client) DeleteQueryOverrideByKey(auditSession *AuditSession, queryKey string) error {
	c.logger.Debugf("Deleting query %v under %v", queryKey, auditSession.String())
	response, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", auditSession.ID, url.QueryEscape(queryKey)), nil, nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return err
	}

	_, err = c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)

	return err
}

func (c Cx1Client) CreateQueryOverride(auditSession *AuditSession, level string, baseQuery *SASTQuery) (SASTQuery, error) {
	c.depwarn("CreateQueryOverride", "CreateSASTQueryOverride")
	return c.CreateSASTQueryOverride(auditSession, level, baseQuery)
}

// When creating overrides, it is best to first fetch the full query collection (via GetSASTQueryCollection) to pass in the base query
func (c Cx1Client) CreateSASTQueryOverride(auditSession *AuditSession, level string, baseQuery *SASTQuery) (SASTQuery, error) {
	var newQuery SASTQuery
	if strings.EqualFold(level, AUDIT_QUERY.APPLICATION) {
		level = AUDIT_QUERY.APPLICATION
		if auditSession.ApplicationID == "" {
			return newQuery, fmt.Errorf("requested to create an application-level query but the current %v for project %v has no application associated", auditSession.String(), auditSession.ProjectName)
		}
	} else if strings.EqualFold(level, AUDIT_QUERY.PROJECT) {
		level = AUDIT_QUERY.PROJECT
	} else if strings.EqualFold(level, AUDIT_QUERY.TENANT) {
		level = AUDIT_QUERY.TENANT
	} else {
		return newQuery, fmt.Errorf("invalid query override level specified ('%v'), use functions cx1client.QueryTypeTenant, QueryTypeApplication, and QueryTypeProduct", level)
	}

	c.logger.Debugf("Create new override of query %v at level %v under %v", baseQuery.String(), level, auditSession.String())

	type NewQuery struct {
		CWE         int64  `json:"cwe"`
		Executable  bool   `json:"executable"`
		Description int64  `json:"description"`
		Language    string `json:"language"`
		Group       string `json:"group"`
		Severity    string `json:"severity"`
		SastID      uint64 `json:"sastId"`
		ID          string `json:"id"`
		Name        string `json:"name"`
		Level       string `json:"level"`
		Path        string `json:"path"`
	}

	newQueryData := NewQuery{
		CWE:         baseQuery.CweID,
		Executable:  baseQuery.IsExecutable,
		Description: baseQuery.QueryDescriptionId,
		Language:    baseQuery.Language,
		Group:       baseQuery.Group,
		Severity:    baseQuery.Severity,
		SastID:      baseQuery.SastID,
		ID:          baseQuery.EditorKey,
		Name:        baseQuery.Name,
		Level:       strings.ToLower(level), // seems to be in lowercase in the post
		Path:        baseQuery.Path,
	}

	jsonBody, _ := json.Marshal(newQueryData)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newQuery, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return newQuery, fmt.Errorf("failed to create query: %s", err)
	}

	responseValue := data.(map[string]interface{})
	newQuery, err = c.GetAuditSASTQueryByKey(auditSession, responseValue["id"].(string))
	if err != nil {
		return newQuery, err
	}

	switch level {
	case AUDIT_QUERY.APPLICATION:
		newQuery.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY.PRODUCT:
		newQuery.LevelID = AUDIT_QUERY.PRODUCT
	case AUDIT_QUERY.PROJECT:
		newQuery.LevelID = auditSession.ProjectID
	case AUDIT_QUERY.TENANT:
		newQuery.LevelID = AUDIT_QUERY.TENANT
	}

	if newQuery.QueryID == 0 {
		newQuery.QueryID = baseQuery.QueryID
	}

	return newQuery, nil
}

// When creating overrides, it is best to first fetch the full query collection (via GetIACQueryCollection) to pass in the base query
func (c Cx1Client) CreateIACQueryOverride(auditSession *AuditSession, level string, baseQuery *IACQuery) (IACQuery, error) {
	var newQuery IACQuery
	if strings.EqualFold(level, AUDIT_QUERY.APPLICATION) {
		level = AUDIT_QUERY.APPLICATION
		if auditSession.ApplicationID == "" {
			return newQuery, fmt.Errorf("requested to create an application-level query but the current %v for project %v has no application associated", auditSession.String(), auditSession.ProjectName)
		}
	} else if strings.EqualFold(level, AUDIT_QUERY.PROJECT) {
		level = AUDIT_QUERY.PROJECT
	} else if strings.EqualFold(level, AUDIT_QUERY.TENANT) {
		level = AUDIT_QUERY.TENANT
	} else {
		return newQuery, fmt.Errorf("invalid query override level specified ('%v'), use functions cx1client.QueryTypeTenant, QueryTypeApplication, and QueryTypeProduct", level)
	}

	if baseQuery == nil {
		return newQuery, fmt.Errorf("base query cannot be nil")
	}

	c.logger.Debugf("Create new override of query %v at level %v under %v", baseQuery.String(), level, auditSession.String())
	if baseQuery.Description == "" {
		c.logger.Tracef("Override of base query %v requires base query's metadata - fetching it now", baseQuery.String())
		q, err := c.GetAuditIACQueryByID(auditSession, baseQuery.QueryID)
		if err != nil {
			return newQuery, err
		}
		baseQuery.MergeQuery(q)
	}

	newQueryData := newIACQuery{
		IACQuery:    *baseQuery,
		ID:          baseQuery.QueryID,
		QueryName:   baseQuery.Name,
		OldSeverity: baseQuery.Severity,
	}

	newQueryData.Level = strings.ToLower(level)

	jsonBody, _ := json.Marshal(newQueryData)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newQuery, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return newQuery, fmt.Errorf("failed to create query: %s", err)
	}

	responseValue := data.(map[string]interface{})
	newQuery, err = c.GetAuditIACQueryByID(auditSession, responseValue["id"].(string))
	if err != nil {
		return newQuery, err
	}

	switch level {
	case AUDIT_QUERY.APPLICATION:
		newQuery.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY.PRODUCT:
		newQuery.LevelID = AUDIT_QUERY.PRODUCT
	case AUDIT_QUERY.PROJECT:
		newQuery.LevelID = auditSession.ProjectID
	case AUDIT_QUERY.TENANT:
		newQuery.LevelID = AUDIT_QUERY.TENANT
	}

	if newQuery.QueryID == "" {
		switch level {
		case AUDIT_QUERY.APPLICATION:
			newQuery.QueryID = "a" + baseQuery.QueryID[1:]
		case AUDIT_QUERY.PROJECT:
			newQuery.QueryID = "p" + baseQuery.QueryID[1:]
		case AUDIT_QUERY.TENANT:
			newQuery.QueryID = "t" + baseQuery.QueryID[1:]
		default:
			c.logger.Warnf("Unknown query level: %v", level)

		}
	}

	newQuery.MergeQuery(*baseQuery)

	return newQuery, nil
}

func (c Cx1Client) CreateNewQuery(auditSession *AuditSession, query SASTQuery) (SASTQuery, []QueryFailure, error) {
	c.depwarn("CreateNewQuery", "CreateNewSASTQuery")
	return c.CreateNewSASTQuery(auditSession, query)
}
func (c Cx1Client) CreateNewSASTQuery(auditSession *AuditSession, query SASTQuery) (SASTQuery, []QueryFailure, error) {
	c.logger.Debugf("Creating new query %v under %v", query.String(), auditSession.String())
	type NewQuery struct {
		Name        string `json:"name"`
		Language    string `json:"language"`
		Group       string `json:"group"`
		Severity    string `json:"severity"`
		Executable  bool   `json:"executable"`
		CWE         int64  `json:"cwe,omitempty"`
		Description int64  `json:"description,omitempty"`
	}

	newQueryData := NewQuery{
		Name:        query.Name,
		Language:    query.Language,
		Group:       query.Group,
		Severity:    query.Severity,
		Executable:  query.IsExecutable,
		CWE:         query.CweID,
		Description: query.QueryDescriptionId,
	}
	if newQueryData.CWE < 0 {
		newQueryData.CWE = 0
	}
	if newQueryData.Description < 0 {
		newQueryData.Description = 0
	}

	var queryFail []QueryFailure

	jsonBody, _ := json.Marshal(newQueryData)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return SASTQuery{}, queryFail, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return SASTQuery{}, queryFail, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return SASTQuery{}, queryFail, fmt.Errorf("failed to create query: %s", err)
	}

	queryKey := data.(map[string]interface{})["id"].(string)

	queryFail, err = c.updateSASTQuerySourceByKey(auditSession, queryKey, query.Source)
	if err != nil {
		return SASTQuery{}, queryFail, err
	}

	newQuery, err := c.GetAuditSASTQueryByKey(auditSession, queryKey)
	return newQuery, queryFail, err
}

func (c Cx1Client) CreateNewIACQuery(auditSession *AuditSession, query IACQuery) (IACQuery, []QueryFailure, error) {
	c.logger.Debugf("Creating new query %v under %v", query.String(), auditSession.String())
	type NewQuery struct {
		Category       string `json:"category"`
		CloudProvider  string `json:"cloudprovider,omitempty"`
		CWE            string `json:"cwe"`
		Description    string `json:"description"`
		DescriptionUrl string `json:"descriptionurl"`
		Platform       string `json:"platform"`
		Name           string `json:"queryname"`
		Severity       string `json:"severity"`
	}

	newQueryData := NewQuery{
		Category:       query.Category,
		CloudProvider:  query.Group,
		CWE:            query.CWE,
		Description:    query.Description,
		DescriptionUrl: query.DescriptionURL,
		Platform:       query.Platform,
		Name:           query.Name,
		Severity:       query.Severity,
	}

	if cmp, err := cxVersion.CheckCxOne("3.43.0"); err == nil && cmp < 0 { // current version is below 3.43
		newQueryData.CloudProvider = ""
	}

	var queryFail []QueryFailure

	jsonBody, _ := json.Marshal(newQueryData)
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return IACQuery{}, queryFail, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return IACQuery{}, queryFail, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return IACQuery{}, queryFail, fmt.Errorf("failed to create query: %s", err)
	}

	queryKey := data.(map[string]interface{})["id"].(string)

	queryFail, err = c.updateIACQuerySourceByID(auditSession, queryKey, query.Source)
	if err != nil {
		return IACQuery{}, queryFail, err
	}

	new_query, err := c.GetAuditIACQueryByID(auditSession, queryKey)
	new_query.MergeQuery(query)
	return new_query, queryFail, err
}

/*
This function will update the query metadata, however currently only the Severity of a query can be changed.
Changes to CWE, description, and other fields will not take effect.
Also, the data returned by the query-editor api does not include the query ID, so it will be 0. Use "UpdateQueryMetadata" wrapper instead to address that.
*/
func (c Cx1Client) UpdateQueryMetadataByKey(auditSession *AuditSession, queryKey string, metadata AuditSASTQueryMetadata) error {
	c.depwarn("UpdateQueryMetadataByKey", "UpdateSASTQueryMetadataByKey")
	return c.updateSASTQueryMetadataByKey(auditSession, queryKey, metadata)
}
func (c Cx1Client) updateSASTQueryMetadataByKey(auditSession *AuditSession, queryKey string, metadata AuditSASTQueryMetadata) error {
	c.logger.Debugf("Updating sast query metadata by key: %v", queryKey)
	jsonBody, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/metadata", auditSession.ID, url.QueryEscape(queryKey)), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %s", err)
	}

	_, err = c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) updateIACQueryMetadataByKey(auditSession *AuditSession, queryKey string, metadata AuditIACQueryMetadata) error {
	c.logger.Debugf("Updating iac query metadata by key: %v", queryKey)
	jsonBody, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/metadata", auditSession.ID, url.QueryEscape(queryKey)), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %s", err)
	}

	_, err = c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) UpdateQueryMetadata(auditSession *AuditSession, query SASTQuery, metadata AuditSASTQueryMetadata) (SASTQuery, error) {
	c.depwarn("UpdateQueryMetadata", "UpdateSASTQueryMetadata")
	return c.UpdateSASTQueryMetadata(auditSession, query, metadata)
}
func (c Cx1Client) UpdateSASTQueryMetadata(auditSession *AuditSession, query SASTQuery, metadata AuditSASTQueryMetadata) (SASTQuery, error) {
	if query.EditorKey == "" {
		return SASTQuery{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	if !query.MetadataDifferent(metadata) {
		c.logger.Debugf("Query metadata for %v unchanged, skipping update", query.StringDetailed())
		return query, nil
	}
	err := c.updateSASTQueryMetadataByKey(auditSession, query.EditorKey, metadata)
	if err != nil {
		return query, err
	}
	newQuery, err := c.GetAuditSASTQueryByKey(auditSession, query.EditorKey)
	if err != nil {
		return query, err
	}
	newQuery.MergeQuery(query)
	return newQuery, nil
}

func (c Cx1Client) UpdateIACQueryMetadata(auditSession *AuditSession, query IACQuery, metadata AuditIACQueryMetadata) (IACQuery, error) {
	if query.QueryID == "" {
		return IACQuery{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	if !query.MetadataDifferent(metadata) {
		c.logger.Debugf("Query metadata for %v unchanged, skipping update", query.StringDetailed())
		return query, nil
	}

	err := c.updateIACQueryMetadataByKey(auditSession, query.QueryID, metadata)
	if err != nil {
		return query, err
	}
	newQuery, err := c.GetAuditIACQueryByID(auditSession, query.QueryID)
	if err != nil {
		return query, err
	}
	newQuery.MergeQuery(query)
	return newQuery, nil
}

func (c Cx1Client) updateSASTQuerySourceByKey(auditSession *AuditSession, queryKey, source string) ([]QueryFailure, error) {
	queryFail, err := c.updateQuerySourceByKey(auditSession, queryKey, source)
	if err != nil {
		return queryFail, err
	}

	/*queryFail, err = c.ValidateQuerySourceByKey(auditSession, queryKey, source)
	if err != nil {
		return SASTQuery{}, queryFail, err
	}*/
	return queryFail, err
}

func (c Cx1Client) updateIACQuerySourceByID(auditSession *AuditSession, queryId, source string) ([]QueryFailure, error) {
	queryFail, err := c.updateQuerySourceByKey(auditSession, queryId, source)
	if err != nil {
		return queryFail, err
	}

	/*queryFail, err := c.ValidateQuerySourceByKey(auditSession, queryKey, source)
	if err != nil {
		return IACQuery{}, queryFail, err
	}*/

	return queryFail, err

}

func (c Cx1Client) updateQuerySourceByKey(auditSession *AuditSession, queryKey, source string) ([]QueryFailure, error) {
	c.logger.Debugf("Updating query source by key: %v", queryKey)
	var queryFail []QueryFailure
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	postbody := make([]QueryUpdate, 1)
	postbody[0].ID = queryKey
	postbody[0].Source = source

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/source", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return queryFail, fmt.Errorf("failed to save source: %s", err)
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	responseObj, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
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

			if len(queryFail) == 1 {
				return queryFail, fmt.Errorf("failed to save source")
			} else {
				return queryFail, nil
			}
		}
	}
	return queryFail, err
}

// This function
func (c Cx1Client) UpdateSASTQuery(auditSession *AuditSession, query SASTQuery) (SASTQuery, []QueryFailure, error) {
	if query.EditorKey == "" {
		return query, []QueryFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditSASTQueries* calls", query.String())
	}

	queryFail, err := c.updateSASTQuerySourceByKey(auditSession, query.EditorKey, query.Source)
	if err != nil {
		return query, queryFail, err
	}

	err = c.updateSASTQueryMetadataByKey(auditSession, query.EditorKey, query.GetMetadata())
	if err != nil {
		return query, queryFail, err
	}

	updatedQuery, err := c.GetAuditSASTQueryByKey(auditSession, query.EditorKey)
	return updatedQuery, queryFail, err
}
func (c Cx1Client) UpdateIACQuery(auditSession *AuditSession, query IACQuery) (IACQuery, []QueryFailure, error) {
	if query.QueryID == "" {
		return query, []QueryFailure{}, fmt.Errorf("query %v does not have an ID, this should be retrieved with the GetAuditIACQueries* calls", query.String())
	}

	/*
		updatedQuerySrc, queryFail, err := c.updateIACQuerySourceByID(auditSession, query.QueryID, query.Source)
		if err != nil {
			return query, queryFail, err
		}

		updatedQueryMeta, err := c.updateIACQueryMetadataByKey(auditSession, query.QueryID, query.GetMetadata())
		updatedQueryMeta.MergeQuery(updatedQuerySrc)
		updatedQueryMeta.MergeQuery(query)*/

	updatedQuery, queryFail, err := c.UpdateIACQuerySource(auditSession, query, query.Source)
	if err != nil {
		return updatedQuery, queryFail, err
	}

	updatedQuery, err = c.UpdateIACQueryMetadata(auditSession, updatedQuery, query.GetMetadata())

	return updatedQuery, queryFail, err
}

func (c Cx1Client) UpdateSASTQuerySource(auditSession *AuditSession, query SASTQuery, source string) (SASTQuery, []QueryFailure, error) {
	if query.EditorKey == "" {
		return SASTQuery{}, []QueryFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	if source == query.Source {
		c.logger.Debugf("Attempted to update source code but it is unchanged, skipping")
		return query, []QueryFailure{}, nil
	}
	queryFail, err := c.updateSASTQuerySourceByKey(auditSession, query.EditorKey, source)
	if err != nil {
		return query, queryFail, err
	}

	newQuery, err := c.GetAuditSASTQueryByKey(auditSession, query.EditorKey)
	if err != nil {
		return query, queryFail, err
	}
	newQuery.MergeQuery(query)
	return newQuery, queryFail, nil
}
func (c Cx1Client) UpdateIACQuerySource(auditSession *AuditSession, query IACQuery, source string) (IACQuery, []QueryFailure, error) {
	if query.QueryID == "" {
		return IACQuery{}, []QueryFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	if source == query.Source {
		c.logger.Debugf("Attempted to update source code but it is unchanged, skipping")
		return query, []QueryFailure{}, nil
	}
	queryFail, err := c.updateIACQuerySourceByID(auditSession, query.QueryID, source)
	if err != nil {
		return query, queryFail, err
	}
	newQuery, err := c.GetAuditIACQueryByID(auditSession, query.QueryID)
	if err != nil {
		return query, queryFail, err
	}
	newQuery.MergeQuery(query)
	return newQuery, queryFail, nil
}

/*
The data returned by the query-editor api does not include the query ID, so it will be 0. Use "ValidateQuerySource" wrapper instead to address that.
This will test if the code compiles and will not update the source code in Cx1 nor in the query object
*/
func (c Cx1Client) ValidateQuerySourceByKey(auditSession *AuditSession, queryKey, source string) ([]QueryFailure, error) {
	c.logger.Debugf("Validating query source by key: %v", queryKey)
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	var queryFail []QueryFailure
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

	responseObj, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
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

/*
This will test if the code compiles and will not update the source code in Cx1 nor in the query object
*/
func (c Cx1Client) ValidateQuerySource(auditSession *AuditSession, query *SASTQuery, source string) ([]QueryFailure, error) {
	c.depwarn("ValidateQuerySource", "ValidateSASTQuerySource")
	return c.ValidateSASTQuerySource(auditSession, query, source)
}
func (c Cx1Client) ValidateSASTQuerySource(auditSession *AuditSession, query *SASTQuery, source string) ([]QueryFailure, error) {
	if query.EditorKey == "" {
		return []QueryFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.ValidateQuerySourceByKey(auditSession, query.EditorKey, source)
}

/*
The data returned by the query-editor api does not include the query ID, so it will be 0. Use "RunQuery" wrapper instead to address that.
This will run the query, but Cx1ClientGo does not currently support retrieving the results - this function is a temporary substitute for
ValidateQuerySource which does not return compilation errors (as of Cx1 version 3.25)
*/
func (c Cx1Client) RunQueryByKey(auditSession *AuditSession, queryKey, source string) (QueryFailure, error) {
	c.logger.Debugf("Running query by key: %v", queryKey)
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	postbody := make([]QueryUpdate, 1)
	postbody[0].ID = queryKey
	postbody[0].Source = source

	var queryFail QueryFailure

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries/run", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return queryFail, fmt.Errorf("failed to run: %s", err)
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return queryFail, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	responseObj, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return queryFail, fmt.Errorf("failed due to %s: %v", err, responseObj)
	}

	if responseMap, ok := responseObj.(map[string]interface{}); ok {
		if val, ok := responseMap["failed_queries"]; ok {
			var failedQueries []QueryFailure

			bytes, _ := json.Marshal(val)
			err = json.Unmarshal(bytes, &failedQueries)
			if err != nil {
				return queryFail, fmt.Errorf("failed to unmarshal failure: %s", err)
			}
			if len(failedQueries) == 1 {
				return failedQueries[0], fmt.Errorf("failed to run query")
			} else {
				return queryFail, fmt.Errorf("failed to run queries, details: %v", failedQueries)
			}
		}
	}
	return queryFail, nil
}

/*
This will test if the code compiles and will not update the source code in Cx1 nor in the query object
*/
func (c Cx1Client) RunQuery(auditSession *AuditSession, query *SASTQuery, source string) (QueryFailure, error) {
	c.depwarn("RunQuery", "RunSASTQuery")
	return c.RunSASTQuery(auditSession, query, source)
}
func (c Cx1Client) RunSASTQuery(auditSession *AuditSession, query *SASTQuery, source string) (QueryFailure, error) {
	if query.EditorKey == "" {
		return QueryFailure{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	return c.RunQueryByKey(auditSession, query.EditorKey, source)
}

// This function will fill the metadata (severity etc) for all queries in the
func (c Cx1Client) GetIACCollectionAuditMetadata(auditSession *AuditSession, collection *IACQueryCollection, customOnly bool) error {
	for pid := range collection.Platforms {
		for gid := range collection.Platforms[pid].QueryGroups {
			for qid, query := range collection.Platforms[pid].QueryGroups[gid].Queries {
				if query.Custom || !customOnly {
					q, err := c.GetAuditIACQueryByID(auditSession, query.QueryID)
					if err != nil {
						return err
					}
					collection.Platforms[pid].QueryGroups[gid].Queries[qid] = q
				}
			}
		}
	}
	return nil
}

//misc functions

func (q AuditSASTQuery) ToSASTQuery() SASTQuery {
	return SASTQuery{
		QueryID:            0,
		Level:              q.Level,
		LevelID:            q.LevelID,
		Path:               q.Path,
		Modified:           "",
		Source:             q.Source,
		Name:               q.Name,
		Group:              q.Metadata.Group,
		Language:           q.Metadata.Language,
		Severity:           q.Metadata.Severity,
		CweID:              q.Metadata.Cwe,
		IsExecutable:       q.Metadata.IsExecutable,
		QueryDescriptionId: q.Metadata.CxDescriptionID,
		Custom:             q.Level != AUDIT_QUERY.PRODUCT,
		EditorKey:          q.Key,
		SastID:             q.Metadata.SastID,
	}
}

func (q *AuditSASTQuery) CalculateEditorKey() string {
	q.Key = calculateEditorKey(q.Level, q.Metadata.Language, q.Metadata.Group, q.Name)
	return q.Key
}

func (q *SASTQuery) CalculateEditorKey() string {
	q.EditorKey = calculateEditorKey(q.Level, q.Language, q.Group, q.Name)
	return q.EditorKey
}

func calculateEditorKey(level, language, group, name string) string {
	queryID := fmt.Sprintf("%s-%s-%s-%s", level, language, group, name)
	encodedID := base32.StdEncoding.EncodeToString([]byte(queryID))
	return encodedID
}

func (q AuditSASTQuery) CalculateQueryID() (uint64, error) {
	id, err := getAstQueryID(q.Metadata.Language, q.Metadata.Name, q.Metadata.Group)
	return id, err
}

func (q *SASTQuery) CalculateQueryID() (uint64, error) {
	id, err := getAstQueryID(q.Language, q.Name, q.Group)
	if err != nil {
		return 0, err
	}
	q.QueryID = id
	return id, nil
}

func getAstQueryID(language, name, group string) (uint64, error) {
	sourcePath := fmt.Sprintf("queries/%s/%s/%s/%s.cs", language, group, name, name)
	queryID, queryIDErr := hash(sourcePath)
	if queryIDErr != nil {
		return 0, queryIDErr
	}
	return queryID, nil
}

func hash(s string) (uint64, error) {
	h := fnv.New64()
	_, err := h.Write([]byte(s))
	return h.Sum64(), err
}

func (s AuditSession) HasLanguage(language string) bool {
	for _, lang := range s.Languages {
		if strings.EqualFold(lang, language) {
			return true
		}
	}
	return false
}

func (s AuditSession) HasPlatform(platform string) bool {
	for _, p := range s.Platforms {
		if strings.EqualFold(p, platform) {
			return true
		}
	}
	return false
}

func (s AuditSession) String() string {
	var languages []string

	if s.Engine == "sast" {
		languages = s.Languages
	} else {
		languages = s.Platforms
	}

	age := time.Since(s.CreatedAt)
	since_refresh := time.Since(s.LastHeartbeat)
	if s.ProjectID == "" && s.ApplicationID == "" {
		return fmt.Sprintf("%v Audit Session %v (Tenant - %v) [%v/%v]", strings.ToUpper(s.Engine), ShortenGUID(s.ID), strings.Join(languages, ","), age.Round(time.Second).String(), since_refresh.Round(time.Second).String())
	} else if s.ApplicationID == "" {
		return fmt.Sprintf("%v Audit Session %v (Project %v - %v) [%v/%v]", strings.ToUpper(s.Engine), ShortenGUID(s.ID), ShortenGUID(s.ProjectID), strings.Join(languages, ","), age.Round(time.Second).String(), since_refresh.Round(time.Second).String())
	} else {
		return fmt.Sprintf("%v Audit Session %v (Project %v/Application %v - %v) [%v/%v]", strings.ToUpper(s.Engine), ShortenGUID(s.ID), ShortenGUID(s.ProjectID), ShortenGUID(s.ApplicationID), strings.Join(languages, ","), age.Round(time.Second).String(), since_refresh.Round(time.Second).String())
	}
}

func (f AuditSessionFilters) GetKey(engine, language string) (string, error) {
	for eng := range f {
		if strings.EqualFold(eng, engine) {
			for _, lang := range f[eng].Filters {
				if strings.EqualFold(lang.Title, language) {
					return lang.Key, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no language '%v' found for engine '%v'", language, engine)
}

func (q AuditIACQuery) ToIACQuery() IACQuery {
	return IACQuery{
		QueryID:        q.QueryID,
		Level:          q.Level,
		LevelID:        q.LevelID,
		Path:           q.Path,
		Source:         q.Source,
		Name:           q.Name,
		Category:       q.Metadata.Category,
		Platform:       q.Metadata.Platform,
		Severity:       q.Metadata.Severity,
		Custom:         q.Level != AUDIT_QUERY.PRODUCT,
		Description:    q.Metadata.Description,
		DescriptionID:  q.Metadata.DescriptionID,
		DescriptionURL: q.Metadata.DescriptionURL,
		CWE:            q.Metadata.Cwe,
		Key:            q.Key,
	}
}

func (q newIACQuery) MarshalJSON() ([]byte, error) {
	type Alias newIACQuery
	aux := Alias(q)

	data, err := json.Marshal(aux)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	if cmp, err := cxVersion.CheckCxOne("3.43.0"); err == nil && cmp >= 0 { // current version is 3.43+
		if val, ok := m["group"]; ok {
			m["cloudprovider"] = val
			delete(m, "group")
		}

		if val, ok := m["descriptionurl"]; ok {
			m["descriptionUrl"] = val
			delete(m, "descriptionurl")
		}
	}

	return json.Marshal(m)
}
