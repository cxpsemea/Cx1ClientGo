package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

/*
	This is separate from audit.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the generic query-related functions that do not need a valid audit session.
*/

func (c Cx1Client) GetQueryByName_v310(level, levelid, language, group, query string) (AuditQuery_v310, error) {
	c.depwarn("GetQueryByName_v310", "GetQueries + QueryCollection.Get*")
	c.logger.Debugf("Get %v query by name: %v -> %v -> %v", level, language, group, query)

	queries, err := c.GetQueriesByLevelID_v310(level, levelid)
	if err != nil {
		return AuditQuery_v310{}, err
	}

	aq, err := FindQueryByName_v310(queries, level, language, group, query)
	if err != nil {
		return AuditQuery_v310{}, err
	}

	aq.LevelID = levelid

	return aq, nil
}

func (c Cx1Client) GetQueriesByLevelID_v310(level, levelId string) ([]AuditQuery_v310, error) {
	c.depwarn("GetQueryByLevelID_v310", "GetAuditQueryByLevelID")
	c.logger.Debugf("Get all queries for %v", level)

	var url string

	var queries_v310 []AuditQuery_v310

	switch level {
	case AUDIT_QUERY_TENANT:
		url = "/cx-audit/queries"
	case AUDIT_QUERY_PROJECT, AUDIT_QUERY_APPLICATION:
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
	default:
		return queries_v310, fmt.Errorf("invalid level %v, options are currently: %v, %v, or %v", level, AUDIT_QUERY_TENANT, AUDIT_QUERY_APPLICATION, AUDIT_QUERY_PROJECT)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries_v310, err
	}

	err = json.Unmarshal(response, &queries_v310)
	if err != nil {
		return queries_v310, err
	}

	applicationId := ""

	for id := range queries_v310 {
		queries_v310[id].ParsePath()
		switch queries_v310[id].Level {
		case AUDIT_QUERY_TENANT:
			queries_v310[id].LevelID = AUDIT_QUERY_TENANT
		case AUDIT_QUERY_PROJECT:
			queries_v310[id].LevelID = levelId
		case AUDIT_QUERY_APPLICATION:
			if applicationId == "" {
				project, err := c.GetProjectByID(levelId)
				if err != nil {
					return queries_v310, fmt.Errorf("failed to retrieve project with ID %v", levelId)
				}
				if len(*project.Applications) == 0 {
					return queries_v310, fmt.Errorf("project %v has an application-level query defined, but has no application associated", project.String())
				}
				applicationId = (*project.Applications)[0]
			}
			queries_v310[id].LevelID = applicationId
		case AUDIT_QUERY_PRODUCT:
			queries_v310[id].LevelID = AUDIT_QUERY_PRODUCT
		case "Tenant":
			queries_v310[id].LevelID = AUDIT_QUERY_TENANT
		}
	}

	return queries_v310, nil
}

func (c Cx1Client) FindQueryByName_v310(queries []AuditQuery_v310, level, language, group, name string) (AuditQuery_v310, error) {
	return FindQueryByName_v310(queries, level, language, group, name)
}

func FindQueryByName_v310(queries []AuditQuery_v310, level, language, group, name string) (AuditQuery_v310, error) {
	for _, q := range queries {
		if q.Level == level && q.Language == language && q.Group == group && q.Name == name {
			return q, nil
		}
	}

	if level == "Corp" {
		return FindQueryByName_v310(queries, "Tenant", language, group, name)
	}

	return AuditQuery_v310{}, fmt.Errorf("no query found matching [%v] %v -> %v -> %v", level, language, group, name)
}

func (c Cx1Client) DeleteQuery_v310(query AuditQuery_v310) error {
	return c.DeleteQueryByName_v310(query.Level, query.LevelID, query.Language, query.Group, query.Name)
}

func (c Cx1Client) DeleteQueryByName_v310(level, levelID, language, group, query string) error {
	c.depwarn("DeleteQueryByName_v310", "DeleteAuditQueryByName")
	c.logger.Debugf("Delete %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	if levelID == "Tenant" {
		levelID = "Corp"
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", levelID, path), nil, nil)
	if err != nil {
		// currently there's a bug where the response can be error 500 even if it succeeded.

		q, err2 := c.GetQueryByName_v310(level, levelID, language, group, query)
		if err2 != nil {
			c.logger.Warnf("error while deleting query (%s) followed by error while checking if the query was deleted (%s) - assuming the query was deleted", err, err2)
			return nil
		}

		if q.Level != level {
			c.logger.Warnf("While deleting the query an error was returned (%s) but the query was deleted", err)
			return nil
		} else {
			return fmt.Errorf("error while deleting query (%s) and the query %v still exists", err, q)
		}
	}

	return nil
}

func (c Cx1Client) AuditNewQuery_v310(language, group, name string) (AuditQuery_v310, error) {
	c.depwarn("AuditNewQuery_v310", "CreateQueryOverride")
	newQuery, err := c.GetQueryByName_v310(AUDIT_QUERY_TENANT, AUDIT_QUERY_TENANT, language, "CxDefaultQueryGroup", "CxDefaultQuery")
	if err != nil {
		return newQuery, err
	}

	newQuery.Group = group
	newQuery.Name = name
	return newQuery, nil
}

// PUT is the only option to create an override on the project-level (and maybe in the future on application-level)
func (c Cx1Client) UpdateQuery_v310(query AuditQuery_v310) error {
	c.depwarn("UpdateQuery_v310", "UpdateQuery*")
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate_v310{
		Name:     query.Name,
		Path:     query.Path,
		Source:   query.Source,
		Language: query.Language,
		Group:    query.Group,
		Metadata: QueryUpdateMetadata_v310{
			Severity: GetSeverityID(query.Severity),
		},
	}

	return c.UpdateQueries_v310(query.Level, query.LevelID, []QueryUpdate_v310{q})
}

func (c Cx1Client) UpdateQueries_v310(level, levelid string, queries []QueryUpdate_v310) error {
	c.depwarn("UpdateQuery_v310/UpdateQueries_v310", "UpdateQuery*")
	jsonBody, _ := json.Marshal(queries)
	if levelid == "Tenant" {
		levelid = "Corp"
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v", levelid), bytes.NewReader(jsonBody), nil)
	if err != nil {
		if err.Error()[0:8] == "HTTP 405" {
			return fmt.Errorf("this endpoint is no longer available - please use UpdateQuery* instead")
		} else {
			// Workaround to fix issue in CX1: sometimes the query is saved but still throws a 500 error
			c.logger.Warnf("Query update failed with %s but it's buggy, checking if the query was updated anyway", err)

			allqueries, err := c.GetQueriesByLevelID_v310(level, levelid)
			if err != nil {
				return err
			}

			for _, q := range queries {
				aq, err2 := FindQueryByName_v310(allqueries, levelid, q.Language, q.Group, q.Name)
				if err2 != nil {
					return fmt.Errorf("failed to update query %v (%v) %v -> %v -> %v: %s", level, levelid, q.Language, q.Group, q.Name, err2)
				}

				if aq.Source != q.Source {
					return fmt.Errorf("query %v on %v source was not updated", q.Path, level)
				}
				if c.GetSeverityID(aq.Severity) != q.Metadata.Severity {
					return fmt.Errorf("query %v on %v severity was not updated", q.Path, level)
				}

				c.logger.Infof("Query %v on %v was successfully updated despite the error", q.Path, level)
			}
			return nil
		}
	}
	if string(response) == "" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	if responseStruct.Type == "ERROR" {
		return fmt.Errorf("error while saving queries: %v", responseStruct.Message)
	} else {
		return nil
	}
}

func (c Cx1Client) UpdateQueryMetadata_v310(query AuditQuery_v310) error {
	c.depwarn("UpdateQueryMetadata_v310", "UpdateQuery*Metadata")
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate_v310{
		Name:     query.Name,
		Path:     query.Path,
		Source:   query.Source,
		Language: query.Language,
		Group:    query.Group,
		Metadata: QueryUpdateMetadata_v310{
			Severity: GetSeverityID(query.Severity),
		},
	}

	return c.UpdateQueriesMetadata_v310(query.Level, query.LevelID, []QueryUpdate_v310{q})
}

func (c Cx1Client) UpdateQueriesMetadata_v310(level, levelid string, queries []QueryUpdate_v310) error {
	c.depwarn("UpdateQueriesMetadata_v310", "UpdateQuery*Metadata")

	type QueryUpdateMetadataOnly struct {
		Name     string                   `json:"name"`
		Path     string                   `json:"path"`
		Metadata QueryUpdateMetadata_v310 `json:"metadata"`
	}

	var updates []QueryUpdateMetadataOnly
	for _, q := range queries {
		updates = append(updates, QueryUpdateMetadataOnly{
			Name:     q.Name,
			Path:     q.Path,
			Metadata: q.Metadata,
		})
	}

	jsonBody, _ := json.Marshal(updates)
	if levelid == "Tenant" {
		levelid = "Corp"
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v", levelid), bytes.NewReader(jsonBody), nil)
	if err != nil {
		if err.Error()[0:8] == "HTTP 405" {
			return fmt.Errorf("this endpoint is no longer available - please use UpdateQuery* instead")
		} else {
			// Workaround to fix issue in CX1: sometimes the query is saved but still throws a 500 error
			c.logger.Warnf("Query update failed with %s but it's buggy, checking if the query was updated anyway", err)

			allqueries, err := c.GetQueriesByLevelID_v310(level, levelid)
			if err != nil {
				return err
			}

			for _, q := range queries {
				aq, err2 := FindQueryByName_v310(allqueries, levelid, q.Language, q.Group, q.Name)
				if err2 != nil {
					return fmt.Errorf("failed to update query %v (%v) %v -> %v -> %v: %s", level, levelid, q.Language, q.Group, q.Name, err2)
				}

				if aq.Source != q.Source {
					return fmt.Errorf("query %v on %v source was not updated", q.Path, level)
				}

				c.logger.Infof("Query %v on %v was successfully updated despite the error", q.Path, level)
			}
			return nil
		}
	}
	if string(response) == "" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	if responseStruct.Type == "ERROR" {
		return fmt.Errorf("error while saving queries: %v", responseStruct.Message)
	} else {
		return nil
	}
}

func (c Cx1Client) GetQueries_v310() (SASTQueryCollection, error) {
	c.depwarn("GetQueries_v310", "GetQueries/GetAuditQueries*")
	//var qc SASTQueryCollection
	qc, err := c.GetSASTPresetQueries()
	if err != nil {
		return qc, err
	}

	aq, err := c.GetQueriesByLevelID_v310(AUDIT_QUERY_TENANT, "")
	if err != nil {
		return qc, err
	}

	qc.AddAuditQueries_v310(&aq)

	return qc, nil
}

func (qc *SASTQueryCollection) AddAuditQueries_v310(queries *[]AuditQuery_v310) {
	for _, q := range *queries {
		ql := qc.GetQueryLanguageByName(q.Language)

		if ql == nil {
			qc.QueryLanguages = append(qc.QueryLanguages, SASTQueryLanguage{q.Language, []SASTQueryGroup{}})
			ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
		}

		qg := ql.GetQueryGroupByName(q.Group)
		if qg == nil {
			ql.QueryGroups = append(ql.QueryGroups, SASTQueryGroup{q.Group, q.Language, []SASTQuery{q.ToQuery()}})
		} else {
			if qgq := qg.GetQueryByLevelAndName(q.Level, q.LevelID, q.Name); qgq == nil {
				qg.Queries = append(qg.Queries, q.ToQuery())
			} else {
				qgq.MergeQuery(q.ToQuery())
			}
		}
	}
}
