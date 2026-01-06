package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Presets

func (p Preset_v330) String() string {
	return fmt.Sprintf("[%d] %v", p.PresetID, p.Name)
}

func (c *Cx1Client) GetPresets_v330(count uint64) ([]Preset_v330, error) {
	c.depwarn("GetPresets_v330", "Get(SAST|IAC)Presets")
	c.config.Logger.Debugf("Get Cx1 Presets")
	var preset_response struct {
		TotalCount uint64        `json:"totalCount"`
		Presets    []Preset_v330 `json:"presets"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets?limit=%d&include_details=true", count), nil, nil)
	if err != nil {
		return preset_response.Presets, err
	}

	err = json.Unmarshal(response, &preset_response)
	c.config.Logger.Tracef("Got %d presets", len(preset_response.Presets))
	return preset_response.Presets, err
}

func (c *Cx1Client) GetPresetCount_v330() (uint64, error) {
	c.depwarn("GetPresetCount_v330", "Get(SAST|IAC)PresetCount")
	c.config.Logger.Debugf("Get Cx1 Presets count")

	response, err := c.sendRequest(http.MethodGet, "/presets?limit=1", nil, nil)
	if err != nil {
		return 0, err
	}

	var preset_response struct {
		TotalCount uint64 `json:"totalCount"`
	}

	err = json.Unmarshal(response, &preset_response)
	if err != nil {
		c.config.Logger.Tracef("Failed to unmarshal response: %s", err)
		c.config.Logger.Tracef("Response was: %v", string(response))

	}

	return preset_response.TotalCount, err
}

func (c *Cx1Client) GetPresetByName_v330(name string) (Preset_v330, error) {
	c.depwarn("GetPresetByName_v330", "Get(SAST|IAC)PresetByName")
	c.config.Logger.Debugf("Get preset by name %v", name)
	var preset_response struct {
		TotalCount uint64        `json:"totalCount"`
		Presets    []Preset_v330 `json:"presets"`
	}

	params := url.Values{
		"offset":          {"0"},
		"limit":           {"1"},
		"exact_match":     {"true"},
		"include_details": {"true"},
		"name":            {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets?%v", params.Encode()), nil, nil)
	if err != nil {
		return Preset_v330{}, err
	}

	err = json.Unmarshal(response, &preset_response)

	if err != nil {
		return Preset_v330{}, err
	}
	if len(preset_response.Presets) == 0 {
		return Preset_v330{}, fmt.Errorf("no such preset %v found", name)
	}
	return preset_response.Presets[0], nil
}

func (c *Cx1Client) GetPresetByID_v330(id uint64) (Preset_v330, error) {
	c.depwarn("GetPresetByID_v330", "Get(SAST|IAC)PresetByID")
	c.config.Logger.Debugf("Get preset by id %d", id)
	var temp_preset struct {
		Preset_v330
		QueryStr []string `json:"queryIds"`
	}
	var preset Preset_v330

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets/%d", id), nil, nil)
	if err != nil {
		return preset, fmt.Errorf("failed to get preset %d: %s", id, err)
	}

	err = json.Unmarshal(response, &temp_preset)

	preset = Preset_v330{PresetID: temp_preset.PresetID, Name: temp_preset.Name, Description: temp_preset.Description, Custom: temp_preset.Custom}

	preset.QueryIDs = make([]uint64, len(temp_preset.QueryStr))
	for id, q := range temp_preset.QueryStr {
		var u uint64
		u, _ = strconv.ParseUint(q, 0, 64)
		preset.QueryIDs[id] = u
	}

	return preset, err
}

func (c *Cx1Client) GetPresetContents_v330(p *Preset_v330, qc *SASTQueryCollection) error {
	c.depwarn("GetPresetContents_v330", "GetPresetContents")
	c.config.Logger.Tracef("Fetching contents for preset %v", p.PresetID)
	if !p.Filled {
		preset, err := c.GetPresetByID_v330(p.PresetID)
		if err != nil {
			return err
		}
		p.Filled = true
		p.QueryIDs = preset.QueryIDs
	}

	if qc != nil {
		p.LinkQueries(qc)
	}

	return nil
}

func (p *Preset_v330) LinkQueries(qc *SASTQueryCollection) {
	p.Queries = make([]SASTQuery, len(p.QueryIDs))

	for id, qid := range p.QueryIDs {
		q := qc.GetQueryByID(qid)
		if q != nil {
			p.Queries[id] = *q
		}
	}
}

// convenience
func (c *Cx1Client) GetAllPresets_v330() ([]Preset_v330, error) {
	c.depwarn("GetAllPresets_v330", "GetAll(SAST|IAC)Presets")
	count, err := c.GetPresetCount_v330()
	if err != nil {
		return []Preset_v330{}, err
	}

	return c.GetPresets_v330(count)
}

func (p *Preset_v330) AddQueryID(queryId uint64) {
	p.QueryIDs = append(p.QueryIDs, queryId)
}

func (c *Cx1Client) CreatePreset_v330(name, description string, queryIDs []uint64) (Preset_v330, error) {
	c.depwarn("CreatePreset_v330", "Create(SAST|IAC)Preset")
	c.config.Logger.Debugf("Creating preset %v", name)
	var preset Preset_v330

	if len(description) > 60 {
		c.config.Logger.Warnf("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	stringIDs := make([]string, len(queryIDs))
	for id, q := range queryIDs {
		stringIDs[id] = fmt.Sprintf("%d", q)
	}

	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queryIDs":    stringIDs,
		"custom":      true,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return preset, err
	}

	response, err := c.sendRequest(http.MethodPost, "/presets", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return preset, err
	}

	var responseStruct struct {
		Id      uint64 `json:"id"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return preset, err
	}

	return c.GetPresetByID_v330(responseStruct.Id)
}

func (c *Cx1Client) UpdatePreset_v330(preset *Preset_v330) error {
	c.depwarn("UpdatePreset_v330", "Update(SAST|IAC)Preset")
	c.config.Logger.Debugf("Saving preset %v", preset.Name)

	qidstr := make([]string, len(preset.QueryIDs))

	for id, q := range preset.QueryIDs {
		qidstr[id] = fmt.Sprintf("%d", q)
	}

	description := preset.Description
	if len(description) > 60 {
		c.config.Logger.Warnf("Description is longer than 60 characters, will be truncated")
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

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/presets/%d", preset.PresetID), bytes.NewReader(json), nil)
	return err
}

func (c *Cx1Client) DeletePreset_v330(preset *Preset_v330) error {
	c.depwarn("DeletePreset_v330", "DeletePreset")
	c.config.Logger.Debugf("Removing preset %v", preset.Name)
	if !preset.Custom {
		return fmt.Errorf("cannot delete preset %v - this is a product-default preset", preset.String())
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/presets/%d", preset.PresetID), nil, nil)
	return err
}

func (c *Cx1Client) GetPresetQueries_v330() (SASTQueryCollection, error) {
	c.depwarn("GetPresetQueries_v330", "Get(SAST|IAC)PresetQueries")
	queries := []SASTQuery{}

	collection := SASTQueryCollection{}
	response, err := c.sendRequest(http.MethodGet, "/presets/queries", nil, nil)
	if err != nil {
		return collection, err
	}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		c.config.Logger.Tracef("Failed to parse %v", string(response))
	}

	for i := range queries {
		queries[i].IsExecutable = true // all queries in the preset are executable

		if queries[i].Custom {
			queries[i].Level = c.QueryTypeTenant()
			queries[i].LevelID = c.QueryTypeTenant()
		} else {
			queries[i].Level = c.QueryTypeProduct()
			queries[i].LevelID = c.QueryTypeProduct()
		}
	}
	collection.AddQueries(&queries)

	return collection, err
}

func (p Preset_v330) ToPreset(collection *SASTQueryCollection) Preset {
	var preset Preset
	preset.PresetID = fmt.Sprintf("%d", p.PresetID)
	preset.Name = p.Name
	preset.Description = p.Description
	preset.Custom = p.Custom
	preset.Engine = "sast"

	presetCollection := SASTQueryCollection{}
	for _, qid := range p.QueryIDs {
		q := collection.GetQueryByID(qid)
		if q != nil {
			presetCollection.AddQuery(*q)
		}
	}

	preset.QueryFamilies = presetCollection.GetQueryFamilies(true)

	return preset
}

func (p Preset) ToPreset_v330() Preset_v330 {
	var preset Preset_v330
	preset.PresetID, _ = strconv.ParseUint(p.PresetID, 10, 64)
	preset.Name = p.Name
	preset.Description = p.Description
	preset.Custom = p.Custom

	for _, fam := range p.QueryFamilies {
		for _, qidstr := range fam.QueryIDs {
			qid, err := strconv.ParseUint(qidstr, 10, 64)
			if err != nil {
				continue
			}
			preset.AddQueryID(qid)
		}
	}

	return preset
}
