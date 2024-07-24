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

var AUDIT_QUERY_PRODUCT = "Cx"
var AUDIT_QUERY_TENANT = "Corp"
var AUDIT_QUERY_APPLICATION = "Team"
var AUDIT_QUERY_PROJECT = "Project"

type requestIDBody struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Id      string `json:"id"`
}

/*
type requestQueryStatus struct {
	AlreadyExists bool   `json:"alreadyExists"`
	EditorKey     string `json:"id"`
}
*/

func (c Cx1Client) QueryTypeProduct() string {
	return AUDIT_QUERY_PRODUCT
}
func (c Cx1Client) QueryTypeTenant() string {
	return AUDIT_QUERY_TENANT
}
func (c Cx1Client) QueryTypeApplication() string {
	return AUDIT_QUERY_APPLICATION
}
func (c Cx1Client) QueryTypeProject() string {
	return AUDIT_QUERY_PROJECT
}

func (c Cx1Client) AuditCreateSessionByID(engine, projectId, scanId string) (AuditSession, error) {
	c.logger.Debugf("Trying to create audit session for project %v scan %v", projectId, scanId)
	/*available, _, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		return "", err
	}

	if !available {
		return "", fmt.Errorf("audit session not available")
	}*/

	var session AuditSession
	var appId string

	proj, err := c.GetProjectByID(projectId)
	if err != nil {
		c.logger.Errorf("Unknown project %v", projectId)
	} else {
		if len(proj.Applications) == 1 {
			appId = proj.Applications[0]
		} else if len(proj.Applications) > 1 {
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

	session.ProjectID = projectId
	session.ApplicationID = appId

	c.logger.Debugf("Created audit session %v under project %v, app %v", session.ID, session.ProjectID, session.ApplicationID)

	return session, nil
}

func (c Cx1Client) AuditDeleteSession(auditSession *AuditSession) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v", auditSession.ID), nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) AuditGetRequestStatusByID(auditSession *AuditSession, requestId string) (bool, interface{}, error) {
	c.logger.Debugf("Get status of request %v for audit session %v", requestId, auditSession.ID)
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
	c.logger.Debugf("Polling status of request %v for audit session %v", requestId, auditSession.ID)
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
	// TODO: keep track of the last-keepalive and don't spam the server, especially with the polling fix
	_, err := c.sendRequest(http.MethodPatch, fmt.Sprintf("/query-editor/sessions/%v", auditSession.ID), nil, nil)
	if err != nil {
		return err
	}
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
	c.logger.Debugf("Get audit session %v scan sources", auditSession.ID)

	var sourcefiles []AuditScanSourceFile

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/sources", auditSession.ID), nil, nil)
	if err != nil {
		return sourcefiles, err
	}

	err = json.Unmarshal(response, &sourcefiles)
	return sourcefiles, err
}

func (c Cx1Client) AuditRunScanByID(auditSession *AuditSession) error {
	c.logger.Infof("Triggering scan under audit session %v", auditSession.ID)
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

func (q AuditQuery) String() string {
	return fmt.Sprintf("[%v] %v: %v", ShortenGUID(q.Key), q.Level, q.Path)
}

func (c Cx1Client) GetAuditQueryByKey(auditSession *AuditSession, key string) (Query, error) {
	c.logger.Debugf("Get audit query by key: %v", key)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", auditSession.ID, url.QueryEscape(key)), nil, nil)
	if err != nil {
		return Query{}, err
	}

	var q AuditQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return Query{}, err
	}

	query := q.ToQuery()
	switch query.Level {
	case AUDIT_QUERY_APPLICATION:
		query.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY_PRODUCT:
		query.LevelID = AUDIT_QUERY_PRODUCT
	case AUDIT_QUERY_PROJECT:
		query.LevelID = auditSession.ProjectID
	case AUDIT_QUERY_TENANT:
		query.LevelID = AUDIT_QUERY_TENANT
	}

	return query, nil
}

func (c Cx1Client) GetAuditQueriesByLevelID(auditSession *AuditSession, level, levelId string) ([]Query, error) {
	c.logger.Debugf("Get all queries for %v %v", level, levelId)

	var url string
	var queries []Query
	var querytree []AuditQueryTree
	switch level {
	case AUDIT_QUERY_TENANT:
		url = fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID)
	case AUDIT_QUERY_PROJECT:
		url = fmt.Sprintf("/query-editor/sessions/%v/queries?projectId=%v", auditSession.ID, levelId)
	default:
		return queries, fmt.Errorf("invalid level %v, options are currently: %v or %v", level, AUDIT_QUERY_TENANT, AUDIT_QUERY_PROJECT)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &querytree)
	if err != nil {
		return queries, err
	}

	for _, lang := range querytree {
		for _, level := range lang.Children {
			isCustom := true
			if level.Title == "Cx" {
				isCustom = false
			}
			for _, group := range level.Children {
				for _, query := range group.Children {

					var qlevelId string
					switch level.Title {
					case AUDIT_QUERY_APPLICATION:
						if auditSession.ApplicationID == "" {
							c.logger.Errorf("Application-level query but project %v doesn't have an application?", levelId)
						}
						qlevelId = auditSession.ApplicationID
					case AUDIT_QUERY_PRODUCT:
						qlevelId = AUDIT_QUERY_PRODUCT
					case AUDIT_QUERY_PROJECT:
						qlevelId = levelId
					case AUDIT_QUERY_TENANT:
						qlevelId = AUDIT_QUERY_TENANT
					default:
						c.logger.Errorf("Unknown query level: %v", level.Title)
						qlevelId = level.Title
					}

					queries = append(queries, Query{
						QueryID:            0,
						Level:              level.Title,
						LevelID:            qlevelId,
						Path:               fmt.Sprintf("queries/%v/%v/%v/%v.cs", lang.Title, group.Title, query.Title, query.Title),
						Modified:           "",
						Source:             "",
						Name:               query.Title,
						Group:              group.Title,
						Language:           lang.Title,
						Severity:           GetSeverity(GetSeverityID(query.Data.Severity)),
						CweID:              0,
						IsExecutable:       false,
						QueryDescriptionId: 0,
						Custom:             isCustom,
						EditorKey:          query.Key,
						SastID:             0,
					})

				}
			}
		}
	}

	return queries, nil
}

func (c Cx1Client) DeleteQueryOverrideByKey(auditSession *AuditSession, queryKey string) error {
	c.logger.Debugf("Deleting query %v under session %v", queryKey, auditSession.ID)
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

func (c Cx1Client) CreateQueryOverride(auditSession *AuditSession, level string, baseQuery *Query) (Query, error) {
	var newQuery Query
	if strings.EqualFold(level, AUDIT_QUERY_APPLICATION) {
		level = AUDIT_QUERY_APPLICATION
		if auditSession.ApplicationID == "" {
			return newQuery, fmt.Errorf("requested to create an application-level query but the current audit session %v for project %v has no application associated", auditSession.ID, auditSession.ProjectName)
		}
	} else if strings.EqualFold(level, AUDIT_QUERY_PROJECT) {
		level = AUDIT_QUERY_PROJECT
	} else if strings.EqualFold(level, AUDIT_QUERY_TENANT) {
		level = AUDIT_QUERY_TENANT
	} else {
		return newQuery, fmt.Errorf("invalid query override level specified ('%v'), use functions cx1client.QueryTypeTenant, QueryTypeApplication, and QueryTypeProduct", level)
	}

	c.logger.Debugf("Create new override of query %v at level %v under session %v", baseQuery.String(), level, auditSession.ID)

	/*baseQuery, err := c.GetAuditQueryByKey(auditSession, queryKey)
	if err != nil {
		return newQuery, err
	}*/

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
	newQuery, err = c.GetAuditQueryByKey(auditSession, responseValue["id"].(string))
	if err != nil {
		return newQuery, err
	}

	switch level {
	case AUDIT_QUERY_APPLICATION:
		newQuery.LevelID = auditSession.ApplicationID
	case AUDIT_QUERY_PRODUCT:
		newQuery.LevelID = AUDIT_QUERY_PRODUCT
	case AUDIT_QUERY_PROJECT:
		newQuery.LevelID = auditSession.ProjectID
	case AUDIT_QUERY_TENANT:
		newQuery.LevelID = AUDIT_QUERY_TENANT
	}

	if newQuery.QueryID == 0 {
		newQuery.QueryID = baseQuery.QueryID
	}

	return newQuery, nil
}

func (c Cx1Client) CreateNewQuery(auditSession *AuditSession, query Query) (Query, error) {
	c.logger.Debugf("Creating new query %v under session %v", query.String(), auditSession.ID)
	type NewQuery struct {
		Name        string `json:"name"`
		Language    string `json:"language"`
		Group       string `json:"group"`
		Severity    string `json:"severity"`
		Executable  bool   `json:"executable"`
		CWE         int64  `json:"cwe"`
		Description int64  `json:"description"`
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

	jsonBody, _ := json.Marshal(newQueryData)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return Query{}, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return Query{}, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return Query{}, fmt.Errorf("failed to create query: %s", err)
	}

	queryKey := data.(map[string]interface{})["id"].(string)

	return c.UpdateQuerySourceByKey(auditSession, queryKey, query.Source)
}

/*
This function will update the query metadata, however currently only the Severity of a query can be changed.
Changes to CWE, description, and other fields will not take effect.
Also, the data returned by the query-editor api does not include the query ID, so it will be 0. Use "UpdateQueryMetadata" wrapper instead to address that.
*/
func (c Cx1Client) UpdateQueryMetadataByKey(auditSession *AuditSession, queryKey string, metadata AuditQueryMetadata) (Query, error) {
	c.logger.Debugf("Updating query metadata by key: %v", queryKey)
	jsonBody, err := json.Marshal(metadata)
	if err != nil {
		return Query{}, err
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/metadata", auditSession.ID, url.QueryEscape(queryKey)), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return Query{}, err
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return Query{}, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	_, err = c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return Query{}, err
	}

	return c.GetAuditQueryByKey(auditSession, queryKey)
}

func (c Cx1Client) UpdateQueryMetadata(auditSession *AuditSession, query *Query, metadata AuditQueryMetadata) (Query, error) {
	if query.EditorKey == "" {
		return Query{}, fmt.Errorf("Query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	newQuery, err := c.UpdateQueryMetadataByKey(auditSession, query.EditorKey, metadata)
	if err != nil {
		return Query{}, err
	}
	newQuery.MergeQuery(*query)
	return newQuery, nil
}

/*
The data returned by the query-editor api does not include the query ID, so it will be 0. Use "UpdateQueryMetadata" wrapper instead to address that.
*/
func (c Cx1Client) UpdateQuerySourceByKey(auditSession *AuditSession, queryKey, source string) (Query, error) {
	c.logger.Debugf("Updating query source by key: %v", queryKey)
	var newQuery Query
	type QueryUpdate struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	postbody := make([]QueryUpdate, 1)
	postbody[0].ID = queryKey
	postbody[0].Source = source

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/source", auditSession.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newQuery, fmt.Errorf("failed to save source: %s", err)
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	responseObj, err := c.AuditRequestStatusPollingByID(auditSession, responseBody.Id)
	if err != nil {
		return newQuery, fmt.Errorf("failed due to %s: %v", err, responseObj)
	}

	if responseMap, ok := responseObj.(map[string]interface{}); ok {
		if val, ok := responseMap["failed_queries"]; ok {
			return newQuery, fmt.Errorf("failed to save source, details: %v", val)
		}
	}

	newAuditQuery, err := c.GetAuditQueryByKey(auditSession, queryKey)
	if err != nil {
		return newQuery, err
	}

	return newAuditQuery, nil
}

func (c Cx1Client) UpdateQuerySource(auditSession *AuditSession, query *Query, source string) (Query, error) {
	if query.EditorKey == "" {
		return Query{}, fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}
	newQuery, err := c.UpdateQuerySourceByKey(auditSession, query.EditorKey, source)
	if err != nil {
		return Query{}, err
	}
	newQuery.MergeQuery(*query)
	return newQuery, nil
}

// convenience/wrapper function
func (c Cx1Client) UpdateQuery(auditSession *AuditSession, query *Query) error {
	if query.EditorKey == "" {
		return fmt.Errorf("query %v does not have an editorKey, this should be retrieved with the GetAuditQueries* calls", query.String())
	}

	_, err := c.UpdateQuerySourceByKey(auditSession, query.EditorKey, query.Source)
	if err != nil {
		return err
	}

	_, err = c.UpdateQueryMetadataByKey(auditSession, query.EditorKey, query.GetMetadata())

	return err
}

func (q AuditQuery) ToQuery() Query {
	return Query{
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
		Custom:             q.Level != AUDIT_QUERY_PRODUCT,
		EditorKey:          q.Key,
		SastID:             q.Metadata.SastID,
	}
}

func (q *AuditQuery) CalculateEditorKey() string {
	q.Key = calculateEditorKey(q.Level, q.Metadata.Language, q.Metadata.Group, q.Name)
	return q.Key
}

func (q *Query) CalculateEditorKey() string {
	q.EditorKey = calculateEditorKey(q.Level, q.Language, q.Group, q.Name)
	return q.EditorKey
}

func calculateEditorKey(level, language, group, name string) string {
	queryID := fmt.Sprintf("%s-%s-%s-%s", level, language, group, name)
	encodedID := base32.StdEncoding.EncodeToString([]byte(queryID))
	return encodedID
}

func (q AuditQuery) CalculateQueryID() (uint64, error) {
	id, err := getAstQueryID(q.Metadata.Language, q.Metadata.Name, q.Metadata.Group)
	return id, err
}

func (q *Query) CalculateQueryID() (uint64, error) {
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
