package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

/*
	This is separate from audit.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the generic query-related functions that do not need a valid audit session.
*/

// this struct is used specifically for the to-be-deprecated /cx-audit/queries endpoint
type AuditQuery_v312 struct {
	QueryID            uint64 `json:"Id,string"`
	Level              string
	LevelID            string `json:"-"`
	Path               string
	Modified           string
	Source             string
	Name               string
	Group              string
	Language           string `json:"lang"`
	Severity           string
	Cwe                int64
	IsExecutable       *bool
	CxDescriptionId    int64
	QueryDescriptionId string
	Key                string
	Title              string
}

func (q AuditQuery_v312) ToQuery() SASTQuery {
	return SASTQuery{
		QueryID:            q.QueryID,
		Level:              q.Level,
		LevelID:            q.LevelID,
		Path:               q.Path,
		Modified:           q.Modified,
		Source:             q.Source,
		Name:               q.Name,
		Group:              q.Group,
		Language:           q.Language,
		Severity:           q.Severity,
		CweID:              q.Cwe,
		IsExecutable:       q.IsExecutable,
		QueryDescriptionId: q.CxDescriptionId,
		Custom:             q.Level != AUDIT_QUERY.PRODUCT,
		EditorKey:          q.Key,
		SastID:             0,
	}
}

// This function uses the cx-audit/queries endpoint, which will at some point be deprecated.
func (c *Cx1Client) GetQueriesByLevelID(level, levelId string) (SASTQueryCollection, error) {
	c.depwarn("GetQueriesByLevelID", "GetAuditSASTQueriesByLevelID")
	c.config.Logger.Debugf("Get all queries for %v", level)

	var url string
	collection := SASTQueryCollection{}
	var queries_v312 []AuditQuery_v312
	var queries []SASTQuery
	switch level {
	case AUDIT_QUERY.TENANT:
		url = "/cx-audit/queries"
	case AUDIT_QUERY.PROJECT:
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
	default:
		return collection, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return collection, err
	}

	err = json.Unmarshal(response, &queries_v312)
	if err != nil {
		return collection, err
	}

	applicationId := ""

	for id := range queries_v312 {
		switch queries_v312[id].Level {
		case AUDIT_QUERY.TENANT:
			queries_v312[id].LevelID = c.QueryTypeTenant()
		case AUDIT_QUERY.PROJECT:
			queries_v312[id].LevelID = levelId
		case AUDIT_QUERY.APPLICATION:
			if applicationId == "" {
				project, err := c.GetProjectByID(levelId)
				if err != nil {
					return collection, fmt.Errorf("failed to retrieve project with ID %v", levelId)
				}
				if len(*project.Applications) == 0 {
					return collection, fmt.Errorf("project %v has an application-level query defined, but has no application associated", project.String())
				} else if len(*project.Applications) > 1 {
					return collection, fmt.Errorf("project %v has an application-level query defined, but has multiple application associated", project.String())
				}
				applicationId = (*project.Applications)[0]
			}
			queries_v312[id].LevelID = applicationId
		case AUDIT_QUERY.PRODUCT:
			queries_v312[id].LevelID = c.QueryTypeProduct()
		}

		queries = append(queries, queries_v312[id].ToQuery())
	}

	collection.AddQueries(&queries)

	return collection, nil
}

func (c *Cx1Client) GetQueryMappings() (map[uint64]uint64, error) {
	var mapping map[uint64]uint64 = make(map[uint64]uint64)
	var responsemap struct {
		Mappings []struct {
			AstId  uint64 `json:"astId,string"`
			SastId uint64 `json:"sastId,string"`
		} `json:"mappings"`
	}

	response, err := c.sendRequest(http.MethodGet, "/queries/mappings", nil, nil)
	if err != nil {
		return mapping, err
	}

	err = json.Unmarshal(response, &responsemap)
	if err != nil {
		return mapping, err
	}

	for _, qm := range responsemap.Mappings {
		mapping[qm.SastId] = qm.AstId
	}

	return mapping, nil

}

// convenience
func (c *Cx1Client) GetSeverityID(severity string) uint {
	return GetSeverityID(severity)
}

func GetSeverityID(severity string) uint {
	switch strings.ToUpper(severity) {
	case "INFO":
		return 0
	case "INFORMATION":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return 0
}

func (c *Cx1Client) GetSeverity(severity uint) string {
	return GetSeverity(severity)
}

func (c *Cx1Client) GetCx1QueryFromSAST(sastId uint64, language, group, name string, mapping *map[uint64]uint64, qc *SASTQueryCollection) *SASTQuery {
	if cx1id, ok := (*mapping)[sastId]; ok {
		return qc.GetQueryByID(cx1id)
	}
	return qc.GetQueryByName(language, group, name)
}

func GetSeverity(severity uint) string {
	switch severity {
	case 0:
		return "Info"
	case 1:
		return "Low"
	case 2:
		return "Medium"
	case 3:
		return "High"
	case 4:
		return "Critical"
	}
	return "Unknown"
}

// update self's empty values with nq's non-empty
func (q *SASTQuery) MergeQuery(nq SASTQuery) {
	if q.QueryID == 0 && nq.QueryID != 0 {
		q.QueryID = nq.QueryID
	}
	if q.Path == "" && nq.Path != "" {
		q.Path = nq.Path
	}
	if q.EditorKey == "" && nq.EditorKey != "" {
		q.EditorKey = nq.EditorKey
	}
	if q.Level == "" && nq.Level != "" {
		q.Level = nq.Level
	}
	if q.LevelID == "" && nq.LevelID != "" {
		q.LevelID = nq.LevelID
	}
	if q.Source == "" && nq.Source != "" {
		q.Source = nq.Source
	}
	if nq.IsExecutable != nil {
		q.IsExecutable = nq.IsExecutable
	}
	if q.CweID == 0 && nq.CweID != 0 {
		q.CweID = nq.CweID
	}
	if q.QueryDescriptionId == 0 && nq.QueryDescriptionId != 0 {
		q.QueryDescriptionId = nq.QueryDescriptionId
	}
	if q.SastID == 0 && nq.SastID != 0 {
		q.SastID = nq.SastID
	}
}

func (q *IACQuery) MergeQuery(nq IACQuery) {
	if q.QueryID == "" && nq.QueryID != "" {
		q.QueryID = nq.QueryID
	}
	if q.Key == "" && nq.Key != "" {
		q.Key = nq.Key
	}
	if q.Path == "" && nq.Path != "" {
		q.Path = nq.Path
	}
	if q.Level == "" && nq.Level != "" {
		q.Level = nq.Level
	}
	if q.LevelID == "" && nq.LevelID != "" {
		q.LevelID = nq.LevelID
	}
	if q.Source == "" && nq.Source != "" {
		q.Source = nq.Source
	}
	if q.Category == "" && nq.Category != "" {
		q.Category = nq.Category
	}
	if q.Group == "" && nq.Group != "" {
		q.Group = nq.Group
	}

	if q.Platform == "" && nq.Platform != "" {
		q.Platform = nq.Platform
	}
	if q.Description == "" && nq.Description != "" {
		q.Description = nq.Description
	}
	if q.DescriptionID == "" && nq.DescriptionID != "" {
		q.DescriptionID = nq.DescriptionID
	}
	if q.DescriptionURL == "" && nq.DescriptionURL != "" {
		q.DescriptionURL = nq.DescriptionURL
	}
}

func (q SASTQuery) StringDetailed() string {
	var scope string
	switch q.Level {
	case AUDIT_QUERY.PRODUCT:
		scope = "Product"
	case AUDIT_QUERY.TENANT:
		scope = "Tenant"
	default:
		scope = fmt.Sprintf("%v %v", q.Level, ShortenGUID(q.LevelID))
	}
	exec := "undef"
	if q.IsExecutable != nil {
		if *q.IsExecutable {
			exec = "true"
		} else {
			exec = "false"
		}
	}
	return fmt.Sprintf("%v: %v -> %v -> %v, %v risk [ID %v, Key %v, Exec %s]", scope, q.Language, q.Group, q.Name, q.Severity, ShortenGUID(strconv.FormatUint(q.QueryID, 10)), ShortenGUID(q.EditorKey), exec)
}

func (q SASTQuery) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
func (q IACQuery) String() string {
	return fmt.Sprintf("[%v] %v -> %v -> %v", ShortenGUID(q.Key), q.Platform, q.Group, q.Name)
}
func (q IACQuery) StringDetailed() string {
	var scope string
	switch q.Level {
	case AUDIT_QUERY.PRODUCT:
		scope = "Product"
	case AUDIT_QUERY.TENANT:
		scope = "Tenant"
	default:
		scope = fmt.Sprintf("%v %v", q.Level, ShortenGUID(q.LevelID))
	}
	return fmt.Sprintf("%v: %v -> %v -> %v, %v risk [Key %v]", scope, q.Platform, q.Group, q.Name, q.Severity, ShortenGUID(q.Key))
}

func (q SASTQuery) GetMetadata() AuditSASTQueryMetadata {
	return AuditSASTQueryMetadata{
		Cwe:             q.CweID,
		IsExecutable:    q.IsExecutable,
		CxDescriptionID: q.QueryDescriptionId,
		Language:        q.Language,
		Group:           q.Group,
		Severity:        q.Severity,
		SastID:          q.SastID,
		Name:            q.Name,
	}
}

func (q SASTQuery) MetadataDifferent(metadata AuditSASTQueryMetadata) bool {
	return q.CweID != metadata.Cwe ||
		q.IsExecutable != metadata.IsExecutable ||
		q.QueryDescriptionId != metadata.CxDescriptionID ||
		q.Language != metadata.Language ||
		q.Group != metadata.Group ||
		!strings.EqualFold(q.Severity, metadata.Severity) ||
		q.SastID != metadata.SastID ||
		q.Name != metadata.Name
}

func (q SASTQuery) GetMetadataDiffs(metadata AuditSASTQueryMetadata) []string {
	var diffs []string

	if q.CweID != metadata.Cwe {
		diffs = append(diffs,
			fmt.Sprintf("CweID: %d != %d", q.CweID, metadata.Cwe))
	}

	if q.IsExecutable != metadata.IsExecutable {
		qexecStr := "undefined"
		metaexecStr := "undefined"

		if q.IsExecutable != nil {
			if *q.IsExecutable {
				qexecStr = "TRUE"
			} else {
				qexecStr = "FALSE"
			}
		}
		if metadata.IsExecutable != nil {
			if *metadata.IsExecutable {
				metaexecStr = "TRUE"
			} else {
				metaexecStr = "FALSE"
			}
		}

		diffs = append(diffs, fmt.Sprintf("IsExecutable: %s != %s", qexecStr, metaexecStr))
	}

	if q.QueryDescriptionId != metadata.CxDescriptionID {
		diffs = append(diffs,
			fmt.Sprintf("QueryDescriptionId: %d != %d", q.QueryDescriptionId, metadata.CxDescriptionID))
	}

	if q.Language != metadata.Language {
		diffs = append(diffs,
			fmt.Sprintf("Language: %s != %s", q.Language, metadata.Language))
	}

	if q.Group != metadata.Group {
		diffs = append(diffs,
			fmt.Sprintf("Group: %s != %s", q.Group, metadata.Group))
	}

	if !strings.EqualFold(q.Severity, metadata.Severity) {
		diffs = append(diffs,
			fmt.Sprintf("Severity: %s != %s", q.Severity, metadata.Severity))
	}

	if q.SastID != metadata.SastID {
		diffs = append(diffs,
			fmt.Sprintf("SastID: %d != %d", q.SastID, metadata.SastID))
	}

	if q.Name != metadata.Name {
		diffs = append(diffs,
			fmt.Sprintf("Name: %s != %s", q.Name, metadata.Name))
	}

	return diffs
}

func (q IACQuery) GetMetadata() AuditIACQueryMetadata {
	return AuditIACQueryMetadata{
		Cwe:            q.CWE,
		Aggregation:    "",
		Category:       q.Category,
		Description:    q.Description,
		DescriptionID:  q.DescriptionID,
		DescriptionURL: q.DescriptionURL,
		Platform:       q.Platform,
		QueryID:        q.QueryID,
		Name:           q.Name,
		Severity:       q.Severity,
	}
}

func (q IACQuery) MetadataDifferent(metadata AuditIACQueryMetadata) bool {
	return q.CWE != metadata.Cwe ||
		q.Category != metadata.Category ||
		q.Description != metadata.Description ||
		q.DescriptionID != metadata.DescriptionID ||
		q.DescriptionURL != metadata.DescriptionURL ||
		q.Platform != metadata.Platform ||
		q.QueryID != metadata.QueryID ||
		q.Name != metadata.Name ||
		!strings.EqualFold(q.Severity, metadata.Severity)
}

func (c *Cx1Client) QueryLink(q *SASTQuery) string {
	return fmt.Sprintf("%v/audit/?queryid=%d", c.config.Cx1Url, q.QueryID)
}

func (c *Cx1Client) GetSASTQueryDescription(queryId uint64) (SASTQueryDescription, error) {
	queryDescriptions, err := c.GetSASTQueryDescriptions([]uint64{queryId})
	if err != nil {
		return SASTQueryDescription{}, err
	}
	if len(queryDescriptions) != 1 {
		return SASTQueryDescription{}, fmt.Errorf("expected 1 query description, got %v", len(queryDescriptions))
	}
	return queryDescriptions[0], nil
}

func (c *Cx1Client) GetSASTQueryDescriptions(queryIds []uint64) ([]SASTQueryDescription, error) {
	params := url.Values{}
	// url should end up: "/queries/descriptions?ids=1&ids=2&scan-id=&tenant-id="
	for _, id := range queryIds {
		params.Add("ids", strconv.FormatUint(id, 10))
	}
	params.Add("scan-id", "")
	params.Add("tenant-id", c.GetTenantName())

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/queries/descriptions?%s", params.Encode()), nil, nil)
	if err != nil {
		return nil, err
	}

	var descriptions []SASTQueryDescription
	err = json.Unmarshal(response, &descriptions)
	return descriptions, err
}

// finds the function-calls that are either open (result = Find_Strings();)
// or base (result = base.Find_Missing_HSTS();)
func (q *SASTQuery) GetDependencies(qc *SASTQueryCollection) (OpenCalls, BaseCalls []*SASTQuery, ProductCalls []string) {
	if q.Source == "" {
		return
	}

	base_call := regexp.MustCompile(`([a-zA-Z0-9_]+)\.([a-zA-Z_0-9]+)\(`)
	base_calls := base_call.FindAllStringSubmatch(q.Source, -1)
	if len(base_calls) > 0 {
		for _, matches := range base_calls {

			if strings.EqualFold(matches[1], "base") {
				var qq *SASTQuery = nil
				qq = qc.GetQueryByName(q.Language, q.Group, matches[2])
				if qq != nil {
					if !slices.Contains(BaseCalls, qq) {
						BaseCalls = append(BaseCalls, qq)
						continue
					}
				}
			}
			callstr := matches[1] + "." + matches[2]
			if !slices.Contains(ProductCalls, callstr) {
				ProductCalls = append(ProductCalls, callstr)
			}
		}
	}

	open_call := regexp.MustCompile(`[^.a-zA-Z0-9_]([a-zA-Z_0-9]+)\(`)
	open_calls := open_call.FindAllStringSubmatch(q.Source, -1)
	if len(open_calls) > 0 {
		for _, matches := range open_calls {
			var qq *SASTQuery = nil
			qq = qc.GetQueryByName(q.Language, q.Group, matches[1])
			if qq == nil {
				qq = qc.GetQueryByName(q.Language, "General", matches[1])
			}

			if qq != nil {
				if !slices.Contains(OpenCalls, qq) && !slices.Contains(BaseCalls, qq) {
					OpenCalls = append(OpenCalls, qq)
				}
			} else {
				if !slices.Contains(ProductCalls, matches[1]) {
					ProductCalls = append(ProductCalls, matches[1])
				}
			}
		}
	}

	chained_call := regexp.MustCompile(`\)\.([a-zA-Z_0-9]+)\(`)
	chained_calls := chained_call.FindAllStringSubmatch(q.Source, -1)
	for _, matches := range chained_calls {
		if !slices.Contains(ProductCalls, matches[1]) {
			ProductCalls = append(ProductCalls, matches[1])
		}
	}

	return
}
