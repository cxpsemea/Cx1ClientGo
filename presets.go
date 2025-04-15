package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

// Presets

func (p Preset) String() string {
	if p.Engine == "sast" {
		return fmt.Sprintf("[%v] %v", p.PresetID, p.Name)
	} else {
		return fmt.Sprintf("[%v] %v", ShortenGUID(p.PresetID), p.Name)
	}
}

// Presets do not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c Cx1Client) GetSASTPresets(count uint64) ([]Preset, error) {
	return c.GetPresets("sast", count)
}

// Presets do not include the contents of the preset (query families etc) - use Get*PresetContents to fill or Get*PresetByID
func (c Cx1Client) GetIACPresets(count uint64) ([]Preset, error) {
	return c.GetPresets("IAC", count)
}

func (c Cx1Client) GetPresets(engine string, count uint64) ([]Preset, error) {
	c.logger.Debug("Get Cx1 SAST Presets")
	var preset_response struct {
		TotalCount uint64   `json:"totalCount"`
		Presets    []Preset `json:"presets"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/presets?limit=%d&include_details=true", engine, count), nil, nil)
	if err != nil {
		return preset_response.Presets, err
	}

	err = json.Unmarshal(response, &preset_response)
	if err != nil {
		c.logger.Tracef("Failed to unmarshal response: %s", err)
	}

	for id := range preset_response.Presets {
		preset_response.Presets[id].Engine = engine
	}

	//c.logger.Tracef("Got %d presets", len(preset_response.Presets))

	return preset_response.Presets, err
}

func (c Cx1Client) GetSASTPresetCount() (uint64, error) {
	return c.GetPresetCount("sast")
}
func (c Cx1Client) GetIACPresetCount() (uint64, error) {
	return c.GetPresetCount("iac")
}

func (c Cx1Client) GetPresetCount(engine string) (uint64, error) {
	c.logger.Debug("Get Cx1 SAST Presets count")

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/presets?limit=1", engine), nil, nil)
	if err != nil {
		return 0, err
	}

	var preset_response struct {
		TotalCount uint64 `json:"totalCount"`
	}

	err = json.Unmarshal(response, &preset_response)
	if err != nil {
		c.logger.Tracef("Failed to unmarshal response: %s", err)
		c.logger.Tracef("Response was: %v", string(response))

	}

	return preset_response.TotalCount, err
}

// Does not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c Cx1Client) GetSASTPresetByName(name string) (Preset, error) {
	return c.GetPresetByName("sast", name)
}

// Does not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c Cx1Client) GetIACPresetByName(name string) (Preset, error) {
	return c.GetPresetByName("iac", name)
}

func (c Cx1Client) GetPresetByName(engine, name string) (Preset, error) {
	c.logger.Debugf("Get preset by name %v for %v", name, engine)
	var preset_response struct {
		TotalCount uint64   `json:"totalCount"`
		Presets    []Preset `json:"presets"`
	}

	params := url.Values{
		"offset":          {"0"},
		"limit":           {"1"},
		"exact-match":     {"true"},
		"include-details": {"true"},
		"search-term":     {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/sast/presets?%v", params.Encode()), nil, nil)
	if err != nil {
		return Preset{}, err
	}

	err = json.Unmarshal(response, &preset_response)

	if err != nil {
		return Preset{}, err
	}
	if len(preset_response.Presets) == 0 {
		return Preset{}, fmt.Errorf("no such preset %v found", name)
	}
	preset_response.Presets[0].Engine = engine
	return preset_response.Presets[0], nil
}

func (c Cx1Client) GetPresetByID(engine, id string) (Preset, error) {
	var preset Preset

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/presets/%v", engine, id), nil, nil)
	if err != nil {
		return preset, fmt.Errorf("failed to get preset %v: %s", id, err)
	}

	err = json.Unmarshal(response, &preset)
	preset.Filled = true
	preset.Engine = engine
	return preset, err
}

// Includes the contents (query families/queries) of the preset as well
func (c Cx1Client) GetSASTPresetByID(id uint64) (Preset, error) {
	return c.GetPresetByID("sast", fmt.Sprintf("%d", id))
}

// Includes the contents (query families/queries) of the preset as well
func (c Cx1Client) GetIACPresetByID(id string) (Preset, error) {
	return c.GetPresetByID("iac", id)
}

func (c Cx1Client) GetIACQueryFamilies() ([]string, error) {
	return c.GetQueryFamilies("iac")
}
func (c Cx1Client) GetSASTQueryFamilies() ([]string, error) {
	return c.GetQueryFamilies("sast")
}
func (c Cx1Client) GetQueryFamilies(engine string) ([]string, error) {
	var families []string
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/query-families", engine), nil, nil)
	if err != nil {
		return families, err
	}

	err = json.Unmarshal(response, &families)
	return families, err
}

func (c Cx1Client) GetIACQueryFamilyContents(family string) (IACQueryCollection, error) {
	collection := IACQueryCollection{}
	_, err := c.getQueryFamilyContents("iac", family)
	if err != nil {
		return collection, err
	}

	//collection.AddQueryTree(&tree)

	return collection, nil
}
func (c Cx1Client) GetSASTQueryFamilyContents(family string) (SASTQueryCollection, error) {
	collection := SASTQueryCollection{}
	tree, err := c.getQueryFamilyContents("sast", family)
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&tree)

	return collection, nil
}
func (c Cx1Client) getQueryFamilyContents(engine, family string) ([]AuditQueryTree, error) {
	var families []AuditQueryTree
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/query-families/%v/queries", engine, family), nil, nil)
	if err != nil {
		return families, err
	}
	err = json.Unmarshal(response, &families)
	if err != nil {
		return families, err
	}

	qfamily := []AuditQueryTree{
		{
			IsLeaf: false,
			Title:  family,
			Key:    family,
			Data: struct {
				Level    string
				Severity string
				CWE      int64
				Custom   bool
			}{},
			Children: families,
		},
	}

	return qfamily, err
}

func (c Cx1Client) GetPresetContents(p *Preset) error {
	preset, err := c.GetPresetByID(p.Engine, p.PresetID)
	if err != nil {
		return err
	}
	*p = preset
	return nil
}

func (p Preset) GetSASTQueryCollection(queries SASTQueryCollection) SASTQueryCollection {
	coll := SASTQueryCollection{}

	for _, fam := range p.QueryFamilies {
		for _, qid := range fam.QueryIDs {
			u, _ := strconv.ParseUint(qid, 0, 64)
			if query := queries.GetQueryByLevelAndID(AUDIT_QUERY_PRODUCT, AUDIT_QUERY_PRODUCT, u); query != nil && query.IsExecutable {
				coll.AddQuery(*query)
			}
		}
	}
	return coll
}

/*
func (p *SASTPreset) LinkQueries(qc *SASTQueryCollection) {
	p.SASTQueries = make([]SASTQuery, len(p.SASTQueryIDs))

	for id, qid := range p.SASTQueryIDs {
		q := qc.GetQueryByID(qid)
		if q != nil {
			p.SASTQueries[id] = *q
		}
	}
}
*/

// convenience
func (c Cx1Client) GetAllSASTPresets() ([]Preset, error) {
	count, err := c.GetSASTPresetCount()
	if err != nil {
		return []Preset{}, err
	}

	return c.GetSASTPresets(count)
}

func (c Cx1Client) CreateSASTPreset(name, description string, collection SASTQueryCollection) (Preset, error) {
	c.logger.Debugf("Creating preset %v for sast", name)
	var preset Preset

	if len(description) > 60 {
		c.logger.Warn("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	type queriesFamilyBody struct {
		FamilyName string   `json:"familyName"`
		QueryIDs   []string `json:"queryIds"`
	}

	var queryFamilies []queriesFamilyBody
	for lid := range collection.QueryLanguages {
		foundFamily := false
		for id := range queryFamilies {
			if strings.EqualFold(queryFamilies[id].FamilyName, collection.QueryLanguages[lid].Name) {
				foundFamily = true

				for gid := range collection.QueryLanguages[lid].QueryGroups {
					for qid := range collection.QueryLanguages[lid].QueryGroups[gid].Queries {
						queryId := fmt.Sprintf("%d", collection.QueryLanguages[lid].QueryGroups[gid].Queries[qid].QueryID)

						if !slices.Contains(queryFamilies[id].QueryIDs, queryId) {
							queryFamilies[id].QueryIDs = append(queryFamilies[id].QueryIDs, queryId)
						}
					}
				}
				break
			}
		}
		if !foundFamily {
			newFam := queriesFamilyBody{
				FamilyName: collection.QueryLanguages[lid].Name,
			}
			for gid := range collection.QueryLanguages[lid].QueryGroups {
				for qid := range collection.QueryLanguages[lid].QueryGroups[gid].Queries {
					queryId := fmt.Sprintf("%d", collection.QueryLanguages[lid].QueryGroups[gid].Queries[qid].QueryID)

					if !slices.Contains(newFam.QueryIDs, queryId) {
						newFam.QueryIDs = append(newFam.QueryIDs, queryId)
					}
				}
			}
			queryFamilies = append(queryFamilies, newFam)
		}
	}

	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queries":     queryFamilies,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return preset, err
	}

	response, err := c.sendRequest(http.MethodPost, "/preset-manager/sast/presets", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return preset, err
	}

	var responseStruct struct {
		Id      uint64 `json:"id,string"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return preset, err
	}

	return c.GetSASTPresetByID(responseStruct.Id)
}

/*
func (c Cx1Client) UpdatePreset(preset *SASTPreset) error {
	c.logger.Debugf("Saving sast preset %v", preset.Name)

	qidstr := make([]string, len(preset.QueryIDs))

	for id, q := range preset.QueryIDs {
		qidstr[id] = fmt.Sprintf("%d", q)
	}

	description := preset.Description
	if len(description) > 60 {
		c.logger.Warn("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	body := map[string]interface{}{
		"name":        preset.Name,
		"description": description,
		"queryIds":    qidstr,
	}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/preset-manager/sast/presets/%v", preset.PresetID), bytes.NewReader(json), nil)
	return err
}
*/

func (c Cx1Client) DeletePreset(preset Preset) error {
	c.logger.Debugf("Removing preset %v", preset.Name)
	if !preset.Custom {
		return fmt.Errorf("cannot delete preset %v - this is a product-default preset", preset.String())
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/preset-manager/%v/presets/%v", preset.Engine, preset.PresetID), nil, nil)
	return err
}

func (c Cx1Client) PresetLink(p *Preset) string {
	c.depwarn("PresetLink", "will be removed")
	return fmt.Sprintf("%v/resourceManagement/presets?presetId=%v", c.baseUrl, p.PresetID)
}
