package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
	"golang.org/x/exp/slices"
)

// Get the first count Applications
// uses the pagination behind the scenes
func (c Cx1Client) GetApplications(count uint64) ([]Application, error) {
	c.logger.Debugf("Get Cx1 Applications")

	_, applications, err := c.GetXApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
	}, count)

	return applications, err
}

func (c Cx1Client) GetAllApplications() ([]Application, error) {
	c.logger.Debugf("Get Cx1 Applications")

	_, applications, err := c.GetAllApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
	})

	return applications, err
}

func (c Cx1Client) GetApplicationByID(id string) (Application, error) {
	c.logger.Debugf("Get Cx1 Applications by id: %v", id)
	var application Application
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications/%v", id), nil, nil)
	if err != nil {
		return application, err
	}

	err = json.Unmarshal(response, &application)
	if application.ProjectIds != nil {
		application.originalProjectIds = *application.ProjectIds
	} else {
		application.originalProjectIds = []string{}
	}
	return application, err
}

// Get all applications matching 'name'
// As of 2024-10-17, this function no longer takes a specific limit as a parameter
// To set limits, offsets, and other parameters directly, use GetApplicationsFiltered
func (c Cx1Client) GetApplicationsByName(name string) ([]Application, error) {
	c.logger.Debugf("Get Cx1 Applications by name: %v", name)

	_, applications, err := c.GetAllApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
		Name:       name,
	})

	return applications, err
}

// returns the application matching exactly (case sensitive) the name
func (c Cx1Client) GetApplicationByName(name string) (Application, error) {
	apps, err := c.GetApplicationsByName(name)
	if err != nil {
		return Application{}, err
	}

	for _, a := range apps {
		if a.Name == name {
			return a, nil
		}
	}

	return Application{}, fmt.Errorf("no application found named %v", name)
}

// Underlying function used by many GetApplications* calls
// Returns the number of applications matching the filter and the array of matching applications
// with one page (filter.Offset to filter.Offset+filter.Limit) of results
func (c Cx1Client) GetApplicationsFiltered(filter ApplicationFilter) (uint64, []Application, error) {
	params, _ := query.Values(filter)

	var ApplicationResponse struct {
		BaseFilteredResponse
		Applications []Application
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", params.Encode()), nil, nil)

	if err != nil {
		return ApplicationResponse.FilteredTotalCount, ApplicationResponse.Applications, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)

	for i := range ApplicationResponse.Applications {
		if ApplicationResponse.Applications[i].ProjectIds != nil {
			ApplicationResponse.Applications[i].originalProjectIds = *ApplicationResponse.Applications[i].ProjectIds
		} else {
			ApplicationResponse.Applications[i].originalProjectIds = []string{}
		}
	}

	return ApplicationResponse.FilteredTotalCount, ApplicationResponse.Applications, err
}

// retrieves all applications matching the filter
// using pagination set via filter.Limit or Get/SetPaginationSettings
func (c Cx1Client) GetAllApplicationsFiltered(filter ApplicationFilter) (uint64, []Application, error) {
	var applications []Application

	count, err := c.GetApplicationCountFiltered(filter)
	if err != nil {
		return count, applications, err
	}

	return c.GetXApplicationsFiltered(filter, count)
}

// retrieves the first X applications matching the filter
// using pagination set via filter.Limit or Get/SetPaginationSettings
func (c Cx1Client) GetXApplicationsFiltered(filter ApplicationFilter, count uint64) (uint64, []Application, error) {
	var applications []Application

	_, apps, err := c.GetApplicationsFiltered(filter)
	applications = apps

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(applications)) < count {
		filter.Bump()
		_, apps, err = c.GetApplicationsFiltered(filter)
		applications = append(applications, apps...)
	}

	if uint64(len(applications)) > count {
		return count, applications[:count], err
	}

	return count, applications, err
}

func (c Cx1Client) CreateApplication(appname string) (Application, error) {
	c.logger.Debugf("Create Application: %v", appname)
	data := map[string]interface{}{ // TODO: direct_app ?
		"name":        appname,
		"description": "",
		"criticality": 3,
		"rules":       []ApplicationRule{},
		"tags":        map[string]string{},
	}

	var app Application

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return app, err
	}

	response, err := c.sendRequest(http.MethodPost, "/applications", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while creating application: %s", err)
		return app, err
	}

	err = json.Unmarshal(response, &app)

	return app, err
}

func (c Cx1Client) DeleteApplication(application *Application) error {
	return c.DeleteApplicationByID(application.ApplicationID)
}
func (c Cx1Client) DeleteApplicationByID(applicationId string) error {
	c.logger.Debugf("Delete Application: %v", applicationId)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/applications/%v", applicationId), nil, nil)
	if err != nil {
		c.logger.Tracef("Error while deleting application: %s", err)
		return err
	}

	return nil
}

// convenience
func (c Cx1Client) GetApplicationCount() (uint64, error) {
	c.logger.Debugf("Get Cx1 Project count")

	count, _, err := c.GetApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: 1},
	})

	return count, err
}

func (c Cx1Client) GetApplicationCountByName(name string) (uint64, error) {
	c.logger.Debugf("Get Cx1 Application count by name: %v", name)

	count, _, err := c.GetApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: 1},
		Name:       name,
	})

	return count, err
}

func (c Cx1Client) GetApplicationCountFiltered(filter ApplicationFilter) (uint64, error) {
	filter.Limit = 1
	params, _ := query.Values(filter)
	c.logger.Debugf("Get Cx1 Application count matching filter: %v", params.Encode())

	count, _, err := c.GetApplicationsFiltered(filter)

	return count, err
}

func (a *Application) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(a.ApplicationID), a.Name)
}

func (c Cx1Client) GetOrCreateApplicationByName(name string) (Application, error) {
	app, err := c.GetApplicationByName(name)
	if err == nil {
		return app, nil
	}

	return c.CreateApplication(name)
}

// Directly assign an application to one or more projects
func (c Cx1Client) AssignApplicationToProjectsByIDs(applicationId string, projectIds []string) error {
	if flag, _ := c.CheckFlag("DIRECT_APP_ASSOCIATION_ENABLED"); !flag {
		return fmt.Errorf("direct app association is not enabled")
	}
	var body struct {
		Projects []string `json:"projects"`
	}
	body.Projects = projectIds
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPost, fmt.Sprintf("/applications/%v/projects", applicationId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while assigning application %v to projects: %s", applicationId, err)
		return err
	}
	return nil
}

// Directly remove an application from one or more projects
func (c Cx1Client) RemoveApplicationFromProjectsByIDs(applicationId string, projectIds []string) error {
	if flag, _ := c.CheckFlag("DIRECT_APP_ASSOCIATION_ENABLED"); !flag {
		return fmt.Errorf("direct app association is not enabled")
	}
	var body struct {
		Projects []string `json:"projects"`
	}
	body.Projects = projectIds
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodDelete, fmt.Sprintf("/applications/%v/projects", applicationId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while removing application %v from projects: %s", applicationId, err)
		return err
	}
	return nil
}

// This function patches a application, changing only the fields supplied to the function.
// The application behind the supplied pointer is not changed
// For CheckmarxOne v3.41+
func (c Cx1Client) PatchApplication(application *Application, update ApplicationPatch) error {
	return c.PatchApplicationByID(application.ApplicationID, update)
}

// This function patches a application, changing only the fields supplied to the function.
// For CheckmarxOne v3.41+
func (c Cx1Client) PatchApplicationByID(applicationId string, update ApplicationPatch) error {
	jsonBody, err := json.Marshal(update)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/applications/%v", applicationId), bytes.NewReader(jsonBody), nil)
	return err
}

// This updates all fields of the application based on the content of the Application object.
// The passed-in application object is not modified, you must GetApplication* again for an updated object
func (c Cx1Client) UpdateApplication(app *Application) error {
	c.logger.Debugf("Update application: %v", app.String())

	// This may be temporary depending on how the API changes
	// sending an projectIds array will cause the application's membership in projects to change
	// this can result in unintentional changes, eg:
	//   application is in proj1&proj2, user has access only to proj1
	//   retrieving the application will list only proj1 in the projectIds array
	//   saving the application may unassign the application from proj2
	app_copy := *app
	if app.ProjectIds != nil {
		added := []string{}
		removed := []string{}
		for _, proj := range *app_copy.ProjectIds {
			if !slices.Contains(app_copy.originalProjectIds, proj) {
				added = append(added, proj)
			}
		}
		for _, proj := range app_copy.originalProjectIds {
			if !slices.Contains(*app_copy.ProjectIds, proj) {
				removed = append(removed, proj)
			}
		}
		if len(added) == 0 && len(removed) == 0 { // no changes were made to the projects list, so omit this field when doing the PUT
			app_copy.ProjectIds = nil
		}
	}

	jsonBody, err := json.Marshal(app_copy)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/applications/%v", app.ApplicationID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while updating application: %s", err)
		return err
	}

	return nil
}

// returns the first rule of this type. There should only be one rule of each type.

func (a *Application) GetRuleByID(ruleID string) *ApplicationRule {
	for id := range a.Rules {
		if a.Rules[id].ID == ruleID {
			return &a.Rules[id]
		}
	}
	return nil
}

// returns all rules of this type. There should only be one rule of each type but sometimes there are more.
func (a *Application) GetRulesByType(ruletype string) []ApplicationRule {
	rules := []ApplicationRule{}
	for i := range a.Rules {
		if a.Rules[i].Type == ruletype {
			rules = append(rules, a.Rules[i])
		}
	}
	return rules
}

func (a *Application) AddRule(ruletype, value string) {
	rules := a.GetRulesByType(ruletype)
	if len(rules) == 0 {
		var newrule ApplicationRule
		newrule.Type = ruletype
		newrule.Value = value
		a.Rules = append(a.Rules, newrule)
	} else {
		for _, rule := range rules {
			if rule.Value == value || strings.Contains(fmt.Sprintf(";%v;", rule.Value), fmt.Sprintf(";%v;", value)) {
				return // rule value already contains this value
			}
		}
		rule := a.GetRuleByID(rules[0].ID)
		rule.Value = fmt.Sprintf("%v;%v", rule.Value, value)
	}
}

func (a *Application) RemoveRule(ruleID string) {
	for i := 0; i < len(a.Rules); i++ {
		if ruleID == a.Rules[i].ID {
			a.Rules = append(a.Rules[:i], a.Rules[i+1:]...)
			return
		}
	}
}

// AssignProject will create or update a "project.name.in" type rule to assign the project to the app
func (a *Application) AssignProject(project *Project) {
	a.AddRule("project.name.in", project.Name)

	if !slices.Contains(*a.ProjectIds, project.ProjectID) {
		newProjs := append(*a.ProjectIds, project.ProjectID)
		a.ProjectIds = &newProjs
	}
	if !slices.Contains(*project.Applications, a.ApplicationID) {
		newApps := append(*project.Applications, a.ApplicationID)
		project.Applications = &newApps
	}
}

// UnassignProject will remove the project from the "project.name.in" rule if it's there, and if the rule ends up empty it will remove the rule
func (a *Application) UnassignProject(project *Project) {
	rules := a.GetRulesByType("project.name.in")
	if len(rules) > 0 {
		for _, rule := range rules {
			if strings.Contains(fmt.Sprintf(";%v;", rule.Value), fmt.Sprintf(";%v;", project.Name)) {
				rule_ref := a.GetRuleByID(rule.ID)
				rule_ref.RemoveItem(project.Name)
				if rule_ref.Value == "" {
					a.RemoveRule(rule.ID)
				}
				return
			}
		}
	}

	if slices.Contains(*a.ProjectIds, project.ProjectID) {
		newProjs := slices.Delete(*a.ProjectIds, slices.Index(*a.ProjectIds, project.ProjectID), slices.Index(*a.ProjectIds, project.ProjectID)+1)
		a.ProjectIds = &newProjs
	}
	if slices.Contains(*project.Applications, a.ApplicationID) {
		newApps := slices.Delete(*project.Applications, slices.Index(*project.Applications, a.ApplicationID), slices.Index(*project.Applications, a.ApplicationID)+1)
		project.Applications = &newApps
	}
}

func (ar *ApplicationRule) RemoveItem(item string) {
	rulestr := ";" + ar.Value + ";"
	itemstr := ";" + item + ";"
	if strings.Contains(rulestr, item) {
		rulestr = strings.Replace(rulestr, itemstr, ";", 1)
		rulestr = rulestr[1:] // chop out starting ;
		if len(rulestr) > 0 {
			rulestr = rulestr[:len(rulestr)-1] // chop out ending ;
		}
	}
	ar.Value = rulestr
}

func (ar *ApplicationRule) String() string {
	return fmt.Sprintf("[%v] %v: %v", ShortenGUID(ar.ID), ar.Type, ar.Value)
}
