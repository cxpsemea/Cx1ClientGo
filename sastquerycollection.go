package Cx1ClientGo

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

func (c Cx1Client) GetSASTQueryCollection() (SASTQueryCollection, error) {
	//var qc SASTQueryCollection

	var qc SASTQueryCollection

	qc, err := c.GetSASTPresetQueries()
	if err != nil {
		return qc, err
	}
	aq, err := c.GetQueriesByLevelID(c.QueryTypeTenant(), c.QueryTypeTenant())
	if err != nil {
		return qc, err
	}

	qc.AddCollection(&aq)

	return qc, nil
}

func (qg SASTQueryGroup) GetQueryByName(name string) *SASTQuery {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByID(qid uint64) *SASTQuery {
	for id, q := range qg.Queries {
		if q.QueryID == qid {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByLevelAndName(level, levelID, name string) *SASTQuery {
	for id, q := range qg.Queries {
		if q.Name == name && q.Level == level && q.LevelID == levelID {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id, q := range qg.Queries {
		if q.QueryID == qid && q.LevelID == levelID && q.Level == level {
			return &qg.Queries[id]
		}
	}
	return nil
}
func (qg SASTQueryGroup) findQuery(level, levelID, name string, qid uint64) *SASTQuery {
	var qgq *SASTQuery = nil

	if qid != 0 {
		qgq = qg.GetQueryByLevelAndID(level, levelID, qid)
	} else {
		qgq = qg.GetQueryByLevelAndName(level, levelID, name)
	}

	return qgq
}
func (ql SASTQueryLanguage) findQuery(level, levelID, name string, qid uint64) *SASTQuery {
	for gid := range ql.QueryGroups {
		if qgq := ql.QueryGroups[gid].findQuery(level, levelID, name, qid); qgq != nil {
			return qgq
		}
	}

	return nil
}
func (qc SASTQueryCollection) findQuery(level, levelID, name string, qid uint64) *SASTQuery {
	for lid := range qc.QueryLanguages {
		if qgq := qc.QueryLanguages[lid].findQuery(level, levelID, name, qid); qgq != nil {
			return qgq
		}
	}

	return nil
}

func (ql SASTQueryLanguage) GetQueryByID(qid uint64) *SASTQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql SASTQueryLanguage) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql SASTQueryLanguage) GetQueryGroupByName(name string) *SASTQueryGroup {
	for id, qg := range ql.QueryGroups {
		if strings.EqualFold(qg.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc SASTQueryCollection) GetQueryLanguageByName(language string) *SASTQueryLanguage {
	for id, ql := range qc.QueryLanguages {
		if strings.EqualFold(ql.Name, language) {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}

func (qc SASTQueryCollection) GetQueryByLevelAndName(level, levelID, language, group, query string) *SASTQuery {
	ql := qc.GetQueryLanguageByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByLevelAndName(level, levelID, query)
}

func (qc SASTQueryCollection) GetQueryByName(language, group, query string) *SASTQuery {
	ql := qc.GetQueryLanguageByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByName(query)
}

func (qc SASTQueryCollection) GetQueryByID(qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc SASTQueryCollection) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc *SASTQueryCollection) GetQueryCount() uint {
	var total uint = 0
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			total += uint(len(qc.QueryLanguages[lid].QueryGroups[gid].Queries))
		}
	}
	return total
}

func (qc *SASTQueryCollection) AddQuery(q SASTQuery) {
	if q.QueryID == 0 {
		qgq := qc.GetQueryByName(q.Language, q.Group, q.Name)
		if qgq != nil {
			q.QueryID = qgq.QueryID
		}
	}

	ql := qc.GetQueryLanguageByName(q.Language)

	if ql == nil {
		qc.QueryLanguages = append(qc.QueryLanguages, SASTQueryLanguage{q.Language, []SASTQueryGroup{}})
		ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
	}
	qg := ql.GetQueryGroupByName(q.Group)
	if qg == nil {
		ql.QueryGroups = append(ql.QueryGroups, SASTQueryGroup{q.Group, q.Language, []SASTQuery{q}})
	} else {
		qgq := qg.findQuery(q.Level, q.LevelID, q.Name, q.QueryID)
		if qgq == nil {
			qg.Queries = append(qg.Queries, q)
		} else {
			qgq.MergeQuery(q)
		}
	}
}

/*
This function may not be necessary in the future, it is used to fill in missing fields when creating new queries
*/
func (qc *SASTQueryCollection) UpdateNewQuery(query *SASTQuery) error {
	ql := qc.GetQueryLanguageByName(query.Language)
	if ql == nil {
		return fmt.Errorf("query language '%v' is not included in this query collection, refresh the collection", query.Language)
	}
	qg := ql.GetQueryGroupByName(query.Group)
	if qg == nil {
		return fmt.Errorf("query group '%v' is not included in this query collection, refresh the collection", query.Group)
	}
	qgq := qg.GetQueryByLevelAndName(query.Level, query.LevelID, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	qgq = qg.GetQueryByLevelAndName(AUDIT_QUERY.TENANT, AUDIT_QUERY.TENANT, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	qgq = qg.GetQueryByLevelAndName(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	return fmt.Errorf("query '%v' inherits from an unknown query, refresh the collection", query.Name)
}

func (qc *SASTQueryCollection) AddQueries(queries *[]SASTQuery) {
	for _, q := range *queries {
		qc.AddQuery(q)
	}
}

func (qc *SASTQueryCollection) AddQueryTree(t *[]AuditQueryTree, appId, projectId string, setExecutable bool) {
	for _, lang := range *t {
		for _, level := range lang.Children {
			isCustom := true
			if level.Title == "Cx" || level.Key == "cx" {
				isCustom = false
			}
			for _, group := range level.Children {
				for _, query := range group.Children {
					var qlevelId string
					var qlevel string
					switch level.Title {
					case AUDIT_QUERY.PRODUCT, "Checkmarx predefined":
						qlevelId = AUDIT_QUERY.PRODUCT
						qlevel = AUDIT_QUERY.PRODUCT
					case AUDIT_QUERY.TENANT, "Custom":
						qlevelId = AUDIT_QUERY.TENANT
						qlevel = AUDIT_QUERY.TENANT
					case AUDIT_QUERY.PROJECT:
						qlevelId = projectId
						qlevel = AUDIT_QUERY.PROJECT
					case AUDIT_QUERY.APPLICATION:
						qlevelId = appId
						qlevel = AUDIT_QUERY.APPLICATION
					default:
						//c.logger.Warnf("Unknown query level: %v / %v", level.Title, level.Key)
						qlevelId = level.Title
						qlevel = level.Title
					}

					key := query.Key
					qid, err := strconv.ParseUint(query.Key, 10, 64)
					if err == nil {
						key = ""
					} else {
						qid = 0
					}

					query := SASTQuery{
						QueryID:            qid,
						Level:              qlevel,
						LevelID:            qlevelId,
						Path:               fmt.Sprintf("queries/%v/%v/%v/%v.cs", lang.Title, group.Title, query.Title, query.Title),
						Modified:           "",
						Source:             "",
						Name:               query.Title,
						Group:              group.Title,
						Language:           lang.Title,
						Severity:           GetSeverity(GetSeverityID(query.Data.Severity)),
						CweID:              query.Data.CWE,
						IsExecutable:       setExecutable,
						QueryDescriptionId: 0,
						Custom:             isCustom,
						EditorKey:          key,
						SastID:             0,
					}
					qc.AddQuery(query)
				}
			}
		}
	}

}

func (qc *SASTQueryCollection) AddCollection(collection *SASTQueryCollection) {
	for _, ql := range collection.QueryLanguages {
		oql := qc.GetQueryLanguageByName(ql.Name)
		if oql == nil {
			newql := SASTQueryLanguage{ql.Name, []SASTQueryGroup{}}
			qc.QueryLanguages = append(qc.QueryLanguages, newql)
			oql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
		}
		for _, qg := range ql.QueryGroups {
			oqg := oql.GetQueryGroupByName(qg.Name)
			if oqg == nil {
				newqg := SASTQueryGroup{qg.Name, qg.Language, []SASTQuery{}}
				oql.QueryGroups = append(oql.QueryGroups, newqg)
				oqg = &oql.QueryGroups[len(oql.QueryGroups)-1]
			}

			for _, qq := range qg.Queries {
				qgq := oqg.findQuery(qq.Level, qq.LevelID, qq.Name, qq.QueryID)
				if qgq == nil {
					oqg.Queries = append(oqg.Queries, qq)
				} else {
					qgq.MergeQuery(qq)
				}
			}
		}
	}
}

func (qc *SASTQueryCollection) UpdateFromCollection(collection *SASTQueryCollection) {
	for _, ql := range collection.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for _, qq := range qg.Queries {
				qgq := qc.findQuery(qq.Level, qq.LevelID, qq.Name, qq.QueryID)
				if qgq != nil {
					qgq.MergeQuery(qq)
				}
			}
		}
	}
}

func (qc SASTQueryCollection) GetCustomQueryCollection() SASTQueryCollection {
	var cqc SASTQueryCollection

	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for _, qq := range qg.Queries {
				if qq.Custom {
					cqc.AddQuery(qq)
				}
			}
		}
	}

	return cqc
}

func (qc SASTQueryCollection) GetQueries() []SASTQuery {
	queries := []SASTQuery{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			queries = append(queries, qc.QueryLanguages[lid].QueryGroups[gid].Queries...)
		}
	}

	return queries
}

func (qc SASTQueryCollection) GetQueryIDs() []uint64 {
	queries := []uint64{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			for _, q := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
				queries = append(queries, q.QueryID)
			}
		}
	}

	return queries
}

func (qc SASTQueryCollection) GetQueryFamilies(executableOnly bool) []QueryFamily {
	var queryFamilies []QueryFamily

	for lid := range qc.QueryLanguages {
		lang := &qc.QueryLanguages[lid]
		foundFamily := false
		for id := range queryFamilies {
			if strings.EqualFold(queryFamilies[id].Name, qc.QueryLanguages[lid].Name) {
				foundFamily = true

				for gid := range lang.QueryGroups {
					group := &lang.QueryGroups[gid]
					for qid := range group.Queries {
						query := &group.Queries[qid]
						queryId := fmt.Sprintf("%d", query.QueryID)

						if !slices.Contains(queryFamilies[id].QueryIDs, queryId) && (!executableOnly || query.IsExecutable) {
							queryFamilies[id].QueryIDs = append(queryFamilies[id].QueryIDs, queryId)
						}
					}
				}
				break
			}
		}
		if !foundFamily {
			newFam := QueryFamily{
				Name: qc.QueryLanguages[lid].Name,
			}
			for gid := range lang.QueryGroups {
				group := &lang.QueryGroups[gid]
				for qid := range group.Queries {
					query := &group.Queries[qid]
					queryId := fmt.Sprintf("%d", query.QueryID)

					if !slices.Contains(newFam.QueryIDs, queryId) && (!executableOnly || query.IsExecutable) {
						newFam.QueryIDs = append(newFam.QueryIDs, queryId)
					}
				}
			}
			queryFamilies = append(queryFamilies, newFam)
		}
	}

	return queryFamilies
}

func (c Cx1Client) QueryGroupLink(q *SASTQueryGroup) string {
	return fmt.Sprintf("%v/audit/?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c Cx1Client) QueryLanguageLink(q *SASTQueryLanguage) string {
	return fmt.Sprintf("%v/audit/?language=%v", c.baseUrl, q.Name)
}

func (q SASTQueryGroup) String() string {
	return fmt.Sprintf("%v -> %v", q.Language, q.Name)
}
func (q SASTQueryLanguage) String() string {
	return q.Name
}

// convenience functions for debugging
func (qg SASTQueryGroup) Print(logger Logger) {
	logger.Infof(" - %v group: %v", qg.Language, qg.Name)
	for _, q := range qg.Queries {
		logger.Infof("   - %v", q.StringDetailed())
	}
}
func (ql SASTQueryLanguage) Print(logger Logger) {
	logger.Infof("Language: %v", ql.Name)
	for _, g := range ql.QueryGroups {
		g.Print(logger)
	}
}

func (qc SASTQueryCollection) Print(logger Logger) {
	logger.Infof("Printing query collection")
	for _, l := range qc.QueryLanguages {
		l.Print(logger)
	}
}

func (qc SASTQueryCollection) GetDiffs(collection *SASTQueryCollection) (missing SASTQueryCollection, extra SASTQueryCollection) {
	return collection.GetExtraQueries(&qc), qc.GetExtraQueries(collection)
}

func (qc SASTQueryCollection) GetExtraQueries(collection *SASTQueryCollection) (extra SASTQueryCollection) {
	for _, lang := range qc.QueryLanguages {
		for _, group := range lang.QueryGroups {
			for _, query := range group.Queries {
				if q := collection.findQuery(query.Level, query.LevelID, query.Name, query.QueryID); q == nil {
					extra.AddQuery(query)
				}
			}
		}
	}
	return
}

func (qc SASTQueryCollection) IsSubset(collection *SASTQueryCollection) bool {
	for _, lang := range qc.QueryLanguages {
		for _, group := range lang.QueryGroups {
			for _, query := range group.Queries {
				if q := collection.findQuery(query.Level, query.LevelID, query.Name, query.QueryID); q == nil {
					return false
				}
			}
		}
	}
	return true
}

/*
// not in use, will be used later?
func treeToIACQueries(querytree *[]AuditQueryTree) []IACQuery {
	var queries []IACQuery
	for _, tech := range *querytree {
		for _, level := range tech.Children {
			isCustom := true
			if level.Title == "Cx" {
				isCustom = false
			}
			for _, family := range level.Children {
				for _, query := range family.Children {
					queries = append(queries, IACQuery{
						QueryID:    query.Key,
						Family:     family.Title,
						Platform: tech.Title,
						IsCustom:   isCustom,
					})

				}
			}
		}
	}

	return queries
}
*/
