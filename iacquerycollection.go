package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

func (c Cx1Client) GetIACQueryCollection() (IACQueryCollection, error) {
	qc, err := c.GetIACPresetQueries()
	if err != nil {
		return qc, err
	}
	return qc, nil
}

func (qg IACQueryGroup) GetQueryByName(name string) *IACQuery {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg IACQueryGroup) GetQueryByID(qid string) *IACQuery {
	for id, q := range qg.Queries {
		if q.QueryID == qid {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg IACQueryGroup) GetQueryByKey(key string) *IACQuery {
	for id, q := range qg.Queries {
		if q.Key == key {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg IACQueryGroup) GetQueryByLevelAndName(level, levelID, name string) *IACQuery {
	for id, q := range qg.Queries {
		if q.Name == name && q.Level == level && q.LevelID == levelID {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg IACQueryGroup) GetQueryByLevelAndKey(level, levelID, key string) *IACQuery {
	if key == "" {
		return nil
	}

	for id, q := range qg.Queries {
		if q.Key == key && q.LevelID == levelID && q.Level == level {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg IACQueryGroup) findQuery(level, levelID, name, key string) *IACQuery {
	var qgq *IACQuery = nil

	if key != "" {
		qgq = qg.GetQueryByLevelAndKey(level, levelID, key)
	} else {
		qgq = qg.GetQueryByLevelAndName(level, levelID, name)
	}

	return qgq
}
func (ql IACQueryPlatform) findQuery(level, levelID, name, key string) *IACQuery {
	for gid := range ql.QueryGroups {
		if qgq := ql.QueryGroups[gid].findQuery(level, levelID, name, key); qgq != nil {
			return qgq
		}
	}

	return nil
}
func (qc IACQueryCollection) findQuery(level, levelID, name, key string) *IACQuery {
	for lid := range qc.Platforms {
		if qgq := qc.Platforms[lid].findQuery(level, levelID, name, key); qgq != nil {
			return qgq
		}
	}

	return nil
}

func (ql IACQueryPlatform) GetQueryByID(qid string) *IACQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql IACQueryPlatform) GetQueryByKey(key string) *IACQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByKey(key); q != nil {
			return q
		}
	}
	return nil
}
func (ql IACQueryPlatform) GetQueryByLevelAndKey(level, levelID, key string) *IACQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByLevelAndKey(level, levelID, key); q != nil {
			return q
		}
	}
	return nil
}
func (ql IACQueryPlatform) GetQueryGroupByName(name string) *IACQueryGroup {
	for id, qc := range ql.QueryGroups {
		if strings.EqualFold(qc.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc IACQueryCollection) GetPlatformByName(technology string) *IACQueryPlatform {
	for id, tech := range qc.Platforms {
		if strings.EqualFold(tech.Name, technology) {
			return &qc.Platforms[id]
		}
	}
	return nil
}

func (qc IACQueryCollection) GetQueryByLevelAndName(level, levelID, language, group, query string) *IACQuery {
	ql := qc.GetPlatformByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByLevelAndName(level, levelID, query)
}

func (qc IACQueryCollection) GetQueryByName(language, group, query string) *IACQuery {
	ql := qc.GetPlatformByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByName(query)
}

func (qc IACQueryCollection) GetQueryByID(qid string) *IACQuery {
	if qid == "" {
		return nil
	}

	for id := range qc.Platforms {
		if q := qc.Platforms[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc IACQueryCollection) GetQueryByLevelAndKey(level, levelID, key string) *IACQuery {
	if key == "" {
		return nil
	}

	for id := range qc.Platforms {
		if q := qc.Platforms[id].GetQueryByLevelAndKey(level, levelID, key); q != nil {
			return q
		}
	}
	return nil
}
func (qc *IACQueryCollection) AddQuery(q IACQuery) {
	if q.Group == "" {
		q.Group = "common"
	}

	if q.Key == "" {
		qgq := qc.GetQueryByName(q.Platform, q.Group, q.Name)
		if qgq != nil {
			q.Key = qgq.Key
		} else {
			if q.QueryID[1] == ':' {
				q.Key = q.QueryID[2:]
			} else {
				q.Key = q.QueryID
			}
		}
	}

	qt := qc.GetPlatformByName(q.Platform)

	if qt == nil {
		qc.Platforms = append(qc.Platforms, IACQueryPlatform{q.Platform, []IACQueryGroup{}})
		qt = &qc.Platforms[len(qc.Platforms)-1]
	}
	qg := qt.GetQueryGroupByName(q.Group)
	if qg == nil {
		qt.QueryGroups = append(qt.QueryGroups, IACQueryGroup{q.Group, q.Platform, []IACQuery{q}})
	} else {
		qgq := qg.findQuery(q.Level, q.LevelID, q.Name, q.Key)
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
func (qc *IACQueryCollection) UpdateNewQuery(query *IACQuery) error {
	ql := qc.GetPlatformByName(query.Platform)
	if ql == nil {
		return fmt.Errorf("query language '%v' is not included in this query collection, refresh the collection", query.Platform)
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
func (qc *IACQueryCollection) AddQueryTree(t *[]AuditQueryTree, appId, projectId string) {
	for _, platform := range *t {
		for _, level := range platform.Children {
			isCustom := true
			if level.Title == "Cx" || level.Key == "cx" {
				isCustom = false
			}
			for _, group := range level.Children {
				if !group.IsLeaf {
					for _, query := range group.Children {
						newquery := query.ToIACQuery(level.Title, platform.Title, group.Title, projectId, appId, isCustom)
						qc.AddQuery(newquery)
					}
				} else {
					// as of apr30, 2025, the querytree may have queries on the wrong level - instead of under the group, the group is the query.
					// in those cases, assume it's "common" group
					newquery := group.ToIACQuery(level.Title, platform.Title, "common", projectId, appId, isCustom)
					qc.AddQuery(newquery)
				}
			}
		}

	}

}

func (query AuditQueryTree) ToIACQuery(levelTitle, platformTitle, groupTitle, projectId, appId string, isCustom bool) IACQuery {
	var qlevelId string
	var qlevel string
	var key string
	if levelTitle == AUDIT_QUERY.PRODUCT || levelTitle == "Checkmarx predefined" {
		qlevelId = AUDIT_QUERY.PRODUCT
		qlevel = AUDIT_QUERY.PRODUCT
		key = query.Key
	} else {
		switch query.Key[0] {
		case 't':
			qlevelId = AUDIT_QUERY.TENANT
			qlevel = AUDIT_QUERY.TENANT
			//key = query.Key[2:]
		case 'p':
			qlevelId = projectId
			qlevel = AUDIT_QUERY.PROJECT
			//key = query.Key[2:]
		case 'a':
			qlevelId = appId
			qlevel = AUDIT_QUERY.APPLICATION
			//key = query.Key[2:]
		default:
			//c.logger.Warnf("Unknown query level: %v / %v", levelTitle, level.Key)
			qlevel = AUDIT_QUERY.PRODUCT
			qlevelId = AUDIT_QUERY.PRODUCT
			key = query.Key
		}
	}

	newquery := IACQuery{
		QueryID:  query.Key,
		Level:    qlevel,
		LevelID:  qlevelId,
		Severity: GetSeverity(GetSeverityID(query.Data.Severity)),
		CWE:      fmt.Sprintf("%d", query.Data.CWE),
		Platform: platformTitle,
		Group:    groupTitle,
		Category: "",
		Key:      key,
		Custom:   isCustom,
		Name:     query.Title,
		Path:     "",
		Source:   "",
	}
	return newquery
}

func (qc *IACQueryCollection) AddCollection(collection *IACQueryCollection) {
	for _, ql := range collection.Platforms {
		oql := qc.GetPlatformByName(ql.Name)
		if oql == nil {
			newql := IACQueryPlatform{ql.Name, []IACQueryGroup{}}
			qc.Platforms = append(qc.Platforms, newql)
			oql = &qc.Platforms[len(qc.Platforms)-1]
		}
		for _, qg := range ql.QueryGroups {
			oqg := oql.GetQueryGroupByName(qg.Name)
			if oqg == nil {
				newqg := IACQueryGroup{qg.Name, qg.Platform, []IACQuery{}}
				oql.QueryGroups = append(oql.QueryGroups, newqg)
				oqg = &oql.QueryGroups[len(oql.QueryGroups)-1]
			}

			for _, qq := range qg.Queries {
				qgq := oqg.findQuery(qq.Level, qq.LevelID, qq.Name, qq.Key)
				if qgq == nil {
					oqg.Queries = append(oqg.Queries, qq)
				} else {
					qgq.MergeQuery(qq)
				}
			}
		}
	}
}

func (qc *IACQueryCollection) UpdateFromCollection(collection *IACQueryCollection) {
	for _, qt := range collection.Platforms {
		for _, qg := range qt.QueryGroups {
			for _, qq := range qg.Queries {
				qgq := qc.findQuery(qq.Level, qq.LevelID, qq.Name, qq.Key)
				if qgq != nil {
					qgq.MergeQuery(qq)
				}
			}
		}
	}
}

func (qc IACQueryCollection) GetCustomQueryCollection() IACQueryCollection {
	var cqc IACQueryCollection

	for _, qt := range qc.Platforms {
		for _, qg := range qt.QueryGroups {
			for _, qq := range qg.Queries {
				if qq.Custom {
					cqc.AddQuery(qq)
				}
			}
		}
	}

	return cqc
}

func (qc IACQueryCollection) GetQueryFamilies(_ bool) []QueryFamily {
	var queryFamilies []QueryFamily

	for lid := range qc.Platforms {
		lang := &qc.Platforms[lid]
		foundPlatform := false
		for id := range queryFamilies {
			if strings.EqualFold(queryFamilies[id].Name, qc.Platforms[lid].Name) {
				foundPlatform = true

				for gid := range lang.QueryGroups {
					group := &lang.QueryGroups[gid]
					for qid := range group.Queries {
						query := &group.Queries[qid]

						if !slices.Contains(queryFamilies[id].QueryIDs, query.QueryID) {
							queryFamilies[id].QueryIDs = append(queryFamilies[id].QueryIDs, query.QueryID)
						}
					}
				}
				break
			}
		}
		if !foundPlatform {
			newFam := QueryFamily{
				Name: qc.Platforms[lid].Name,
			}
			for gid := range lang.QueryGroups {
				group := &lang.QueryGroups[gid]
				for qid := range group.Queries {
					query := &group.Queries[qid]
					if !slices.Contains(newFam.QueryIDs, query.QueryID) {
						newFam.QueryIDs = append(newFam.QueryIDs, query.QueryID)
					}
				}
			}
			queryFamilies = append(queryFamilies, newFam)
		}
	}

	return queryFamilies
}

// convenience functions for debugging
func (qg IACQueryGroup) Print(logger Logger) {
	logger.Infof(" - %v group: %v", qg.Platform, qg.Name)
	for _, q := range qg.Queries {
		logger.Infof("   - %v", q.StringDetailed())
	}
}
func (ql IACQueryPlatform) Print(logger Logger) {
	logger.Infof("Platform: %v", ql.Name)
	for _, g := range ql.QueryGroups {
		g.Print(logger)
	}
}
func (qc IACQueryCollection) Print(logger Logger) {
	logger.Infof("Printing query collection")
	for _, l := range qc.Platforms {
		l.Print(logger)
	}
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

func (q *IACQuery) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	if val, ok := m["cloudprovider"]; ok {
		m["group"] = val
		delete(m, "cloudprovider")
	}
	if val, ok := m["descriptionUrl"]; ok {
		m["descriptionurl"] = val
		delete(m, "descriptionUrl")
	}

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	type Alias IACQuery
	return json.Unmarshal(b, (*Alias)(q))
}
