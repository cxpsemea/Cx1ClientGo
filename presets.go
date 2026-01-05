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

func (p Preset) String() string {
	switch p.Engine {
	case "sast":
		return fmt.Sprintf("[%v] %v (sast)", p.PresetID, p.Name)
	case "iac":
		return fmt.Sprintf("[%v] %v (iac)", ShortenGUID(p.PresetID), p.Name)
	default:
		return fmt.Sprintf("[%v] %v (%v)", p.PresetID, p.Name, p.Engine)
	}

}

func (c *Cx1Client) newPresetsEnabled() bool {
	flag, _ := c.CheckFlag("NEW_PRESET_MANAGEMENT_ENABLED")
	if !flag {
		c.config.Logger.Debugf("The New Preset Management feature is not enabled in this environment. Old /api/presets endpoints will be used, but these will be disabled in Cx1 Multi-Tenant EOY 2025 and removed from Cx1ClientGo at that time. Ensure your environment has the new feature if you wish to use newer Cx1ClientGo library versions in 2026.")
	}
	return flag
}

// Presets do not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c *Cx1Client) GetSASTPresets(count uint64) ([]Preset, error) {
	return c.GetPresets("sast", count)
}

// Presets do not include the contents of the preset (query families etc) - use Get*PresetContents to fill or Get*PresetByID
func (c *Cx1Client) GetIACPresets(count uint64) ([]Preset, error) {
	return c.GetPresets("iac", count)
}

func (c *Cx1Client) GetPresets(engine string, count uint64) ([]Preset, error) {
	c.config.Logger.Debugf("Get Cx1 %v Presets", engine)
	if !c.newPresetsEnabled() {
		if engine == "sast" {
			queries, err := c.GetSASTPresetQueries()
			if err != nil {
				return []Preset{}, err
			}

			presets, err := c.GetPresets_v330(count)
			if err != nil {
				return []Preset{}, err
			} else {
				var sastPresets []Preset
				for _, p := range presets {
					sastPresets = append(sastPresets, p.ToPreset(&queries))
				}
				return sastPresets, nil
			}
		}
		return []Preset{}, fmt.Errorf("currently unsupported in this environment, requires flag NEW_PRESET_MANAGEMENT_ENABLED")
	}
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
		c.config.Logger.Tracef("Failed to unmarshal response: %s", err)
	}

	for id := range preset_response.Presets {
		preset_response.Presets[id].Engine = engine
	}

	//c.config.Logger.Tracef("Got %d presets", len(preset_response.Presets))

	return preset_response.Presets, err
}

func (c *Cx1Client) GetSASTPresetCount() (uint64, error) {
	return c.GetPresetCount("sast")
}
func (c *Cx1Client) GetIACPresetCount() (uint64, error) {
	return c.GetPresetCount("iac")
}

func (c *Cx1Client) GetPresetCount(engine string) (uint64, error) {
	c.config.Logger.Debugf("Get Cx1 %v Presets count", engine)

	if !c.newPresetsEnabled() {
		if engine == "sast" {
			return c.GetPresetCount_v330()
		}
		return 0, fmt.Errorf("currently unsupported in this environment, requires flag NEW_PRESET_MANAGEMENT_ENABLED")
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/presets?limit=1", engine), nil, nil)
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

// Does not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c *Cx1Client) GetSASTPresetByName(name string) (Preset, error) {
	return c.GetPresetByName("sast", name)
}

// Does not include the contents of the preset (query families etc) - use GetPresetContents to fill or GetPresetByID
func (c *Cx1Client) GetIACPresetByName(name string) (Preset, error) {
	return c.GetPresetByName("iac", name)
}

func (c *Cx1Client) GetPresetByName(engine, name string) (Preset, error) {
	c.config.Logger.Debugf("Get preset by name %v for %v", name, engine)

	if !c.newPresetsEnabled() {
		if engine == "sast" {
			queries, err := c.GetSASTPresetQueries()
			if err != nil {
				return Preset{}, err
			}

			preset, err := c.GetPresetByName_v330(name)
			if err != nil {
				return Preset{}, err
			}
			return preset.ToPreset(&queries), nil
		}
		return Preset{}, fmt.Errorf("currently unsupported in this environment, requires flag NEW_PRESET_MANAGEMENT_ENABLED")
	}

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

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/presets?%v", engine, params.Encode()), nil, nil)
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

func (c *Cx1Client) GetPresetByID(engine, id string) (Preset, error) {
	var preset Preset
	if !c.newPresetsEnabled() {
		if engine == "sast" {
			queries, err := c.GetSASTPresetQueries()
			if err != nil {
				return Preset{}, err
			}
			id, _ := strconv.ParseUint(id, 10, 64)
			preset, err := c.GetPresetByID_v330(id)
			if err != nil {
				return Preset{}, err
			}
			return preset.ToPreset(&queries), nil
		}
		return Preset{}, fmt.Errorf("currently unsupported in this environment, requires flag NEW_PRESET_MANAGEMENT_ENABLED")
	}

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
func (c *Cx1Client) GetSASTPresetByID(id uint64) (Preset, error) {
	return c.GetPresetByID("sast", fmt.Sprintf("%d", id))
}

// Includes the contents (query families/queries) of the preset as well
func (c *Cx1Client) GetIACPresetByID(id string) (Preset, error) {
	return c.GetPresetByID("iac", id)
}

// this will return a list of queries that can be added to a preset, meaning only executable queries
func (c *Cx1Client) GetSASTPresetQueries() (SASTQueryCollection, error) {
	collection := SASTQueryCollection{}
	if c.newPresetsEnabled() {
		querytree, err := c.getPresetQueries("sast")
		if err != nil {
			return collection, err
		}

		collection.AddQueryTree(&querytree, "", "", true)
		return collection, nil
	} else {
		return c.GetPresetQueries_v330()
	}
}

func (c *Cx1Client) GetIACPresetQueries() (IACQueryCollection, error) {
	collection := IACQueryCollection{}
	querytree, err := c.getPresetQueries("iac")
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&querytree, "", "")
	return collection, nil
}

func (c *Cx1Client) getPresetQueries(engine string) ([]AuditQueryTree, error) {
	families, err := c.GetQueryFamilies(engine)
	querytree := []AuditQueryTree{}
	if err != nil {
		return querytree, err
	}

	for _, fam := range families {
		tree, err := c.getQueryFamilyContents(engine, fam)
		if err != nil {
			return querytree, err
		}
		querytree = append(querytree, tree...)
	}

	return querytree, nil
}

func (c *Cx1Client) GetIACQueryFamilies() ([]string, error) {
	return c.GetQueryFamilies("iac")
}
func (c *Cx1Client) GetSASTQueryFamilies() ([]string, error) {
	return c.GetQueryFamilies("sast")
}
func (c *Cx1Client) GetQueryFamilies(engine string) ([]string, error) {
	var families []string
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/preset-manager/%v/query-families", engine), nil, nil)
	if err != nil {
		return families, err
	}

	err = json.Unmarshal(response, &families)
	return families, err
}

func (c *Cx1Client) GetIACQueryFamilyContents(family string) (IACQueryCollection, error) {
	collection := IACQueryCollection{}
	tree, err := c.getQueryFamilyContents("iac", family)
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&tree, "", "")

	return collection, nil
}
func (c *Cx1Client) GetSASTQueryFamilyContents(family string) (SASTQueryCollection, error) {
	collection := SASTQueryCollection{}
	tree, err := c.getQueryFamilyContents("sast", family)
	if err != nil {
		return collection, err
	}

	collection.AddQueryTree(&tree, "", "", false)

	return collection, nil
}
func (c *Cx1Client) getQueryFamilyContents(engine, family string) ([]AuditQueryTree, error) {
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

func (c *Cx1Client) GetPresetContents(p *Preset) error {
	if p.Engine == "sast" && !c.newPresetsEnabled() {
		queries, err := c.GetSASTPresetQueries()
		if err != nil {
			return err
		}

		preset := p.ToPreset_v330()
		err = c.GetPresetContents_v330(&preset, &queries)
		if err != nil {
			return err
		}
		*p = preset.ToPreset(&queries)
		return nil
	}
	preset, err := c.GetPresetByID(p.Engine, p.PresetID)
	if err != nil {
		return err
	}
	//p.QueryFamilies = preset.QueryFamilies
	*p = preset
	return nil
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
func (c *Cx1Client) GetAllSASTPresets() ([]Preset, error) {
	count, err := c.GetSASTPresetCount()
	if err != nil {
		return []Preset{}, err
	}

	return c.GetSASTPresets(count)
}

func (c *Cx1Client) CreateSASTPreset(name, description string, collection SASTQueryCollection) (Preset, error) {
	c.config.Logger.Debugf("Creating preset %v for sast", name)
	if !c.newPresetsEnabled() {
		new_preset, err := c.CreatePreset_v330(name, description, collection.GetQueryIDs())
		if err != nil {
			return Preset{}, err
		}
		return new_preset.ToPreset(&collection), nil
	}

	if len(description) > 60 {
		c.config.Logger.Warnf("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	queryFamilies := collection.GetQueryFamilies(true)

	presetID, err := c.createPreset("sast", name, description, queryFamilies)
	if err != nil {
		return Preset{}, err
	}
	u, _ := strconv.ParseUint(presetID, 10, 64)
	return c.GetSASTPresetByID(u)
}

func (c *Cx1Client) GetAllIACPresets() ([]Preset, error) {
	count, err := c.GetIACPresetCount()
	if err != nil {
		return []Preset{}, err
	}

	return c.GetIACPresets(count)
}

func (c *Cx1Client) CreateIACPreset(name, description string, collection IACQueryCollection) (Preset, error) {
	c.config.Logger.Debugf("Creating preset %v for iac", name)

	if len(description) > 60 {
		c.config.Logger.Warnf("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	queryFamilies := collection.GetQueryFamilies(true) // true parameter unused for IAC

	presetID, err := c.createPreset("iac", name, description, queryFamilies)
	if err != nil {
		return Preset{}, err
	}
	return c.GetIACPresetByID(presetID)
}

func (c *Cx1Client) createPreset(engine, name, description string, families []QueryFamily) (string, error) {
	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queries":     families,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/preset-manager/%v/presets", engine), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", err
	}

	var responseStruct struct {
		Id      string `json:"id"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	return responseStruct.Id, err
}

func (c *Cx1Client) UpdateSASTPreset(preset Preset) error {
	if !c.newPresetsEnabled() {
		p := preset.ToPreset_v330()
		return c.UpdatePreset_v330(&p)
	}
	c.config.Logger.Debugf("Saving sast preset %v", preset.Name)
	return c.updatePreset("sast", preset.PresetID, preset.Name, preset.Description, preset.QueryFamilies)
}
func (c *Cx1Client) UpdateIACPreset(preset Preset) error {
	c.config.Logger.Debugf("Saving iac preset %v", preset.Name)
	return c.updatePreset("iac", preset.PresetID, preset.Name, preset.Description, preset.QueryFamilies)
}

func (c *Cx1Client) updatePreset(engine, id, name, description string, families []QueryFamily) error {
	if len(description) > 60 {
		c.config.Logger.Warnf("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queries":     families,
	}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/preset-manager/%v/presets/%v", engine, id), bytes.NewReader(json), nil)
	return err
}

func (c *Cx1Client) DeletePreset(preset Preset) error {
	if !c.newPresetsEnabled() {
		p := preset.ToPreset_v330()
		return c.DeletePreset_v330(&p)
	}
	c.config.Logger.Debugf("Removing preset %v", preset.Name)
	if !preset.Custom {
		return fmt.Errorf("cannot delete preset %v - this is a product-default preset", preset.String())
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/preset-manager/%v/presets/%v", preset.Engine, preset.PresetID), nil, nil)
	return err
}

func (c *Cx1Client) PresetLink(p *Preset) string {
	c.depwarn("PresetLink", "will be removed")
	return fmt.Sprintf("%v/resourceManagement/presets?presetId=%v", c.config.BaseUrl, p.PresetID)
}

func (p Preset) GetSASTQueryCollection(queries SASTQueryCollection) SASTQueryCollection {
	coll := SASTQueryCollection{}
	if p.Engine != "sast" {
		return coll
	}

	for _, fam := range p.QueryFamilies {
		for _, qid := range fam.QueryIDs {
			u, _ := strconv.ParseUint(qid, 0, 64)
			if query := queries.GetQueryByLevelAndID(AUDIT_QUERY.PRODUCT, AUDIT_QUERY.PRODUCT, u); query != nil && query.IsExecutable {
				coll.AddQuery(*query)
			}
		}
	}
	return coll
}

func (p Preset) GetIACQueryCollection(queries IACQueryCollection) IACQueryCollection {
	coll := IACQueryCollection{}
	if p.Engine != "iac" {
		return coll
	}

	for _, fam := range p.QueryFamilies {
		for _, qid := range fam.QueryIDs {
			if query := queries.GetQueryByID(qid); query != nil {
				coll.AddQuery(*query)
			}
		}
	}
	return coll
}

func (p *Preset) UpdateQueries(collection QueryCollection) {
	p.QueryFamilies = collection.GetQueryFamilies(true)
}
