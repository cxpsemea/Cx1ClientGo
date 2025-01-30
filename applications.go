package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Applications
func (c Cx1Client) GetApplications(limit uint) ([]Application, error) {
	c.logger.Debug("Get Cx1 Applications")
	var ApplicationResponse struct {
		TotalCount    uint64
		FilteredCount uint64
		Applications  []Application
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", limit)},
		//"sort":       {"+created_at"},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", body.Encode()), nil, nil)

	if err != nil {
		return ApplicationResponse.Applications, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	c.logger.Tracef("Retrieved %d applications", len(ApplicationResponse.Applications))
	return ApplicationResponse.Applications, err
}

func (c Cx1Client) GetApplicationByID(id string) (Application, error) {
	c.logger.Debugf("Get Cx1 Applications by id: %v", id)
	var application Application
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications/%v", id), nil, nil)
	if err != nil {
		return application, err
	}

	err = json.Unmarshal(response, &application)
	return application, err
}

func (c Cx1Client) GetApplicationsByName(name string, limit uint64) ([]Application, error) {
	c.logger.Debugf("Get Cx1 Applications by name: %v", name)

	var ApplicationResponse struct {
		TotalCount    uint64
		FilteredCount uint64
		Applications  []Application
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", limit)},
		"name":  {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", body.Encode()), nil, nil)

	if err != nil {
		return ApplicationResponse.Applications, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	c.logger.Tracef("Retrieved %d applications", len(ApplicationResponse.Applications))
	return ApplicationResponse.Applications, err
}

func (c Cx1Client) GetApplicationByName(name string) (Application, error) {
	apps, err := c.GetApplicationsByName(name, 0)
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

func (c Cx1Client) CreateApplication(appname string) (Application, error) {
	c.logger.Debugf("Create Application: %v", appname)
	data := map[string]interface{}{
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
	c.logger.Debug("Get Cx1 Project count")
	var ApplicationResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", 1)},
		//"sort":       {"+created_at"},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", body.Encode()), nil, nil)

	if err != nil {
		return 0, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	return ApplicationResponse.TotalCount, err
}

func (c Cx1Client) GetApplicationCountByName(name string) (uint64, error) {
	c.logger.Debugf("Get Cx1 Project count by name: %v", name)
	var ApplicationResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", 1)},
		"name":  {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", body.Encode()), nil, nil)

	if err != nil {
		return 0, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	return ApplicationResponse.FilteredTotalCount, err
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

func (c Cx1Client) UpdateApplication(app *Application) error {
	c.logger.Debugf("Update application: %v", app.String())
	jsonBody, err := json.Marshal(*app)
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

/*func (a *Application) GetRuleByType(ruletype string) *ApplicationRule {
	for id := range a.Rules {
		if a.Rules[id].Type == ruletype {
			return &(a.Rules[id])
		}
	}
	return nil
}*/

func (a *Application) GetRulesByType(ruletype string) []*ApplicationRule {
	rules := []*ApplicationRule{}
	for id := range a.Rules {
		if a.Rules[id].Type == ruletype {
			rules = append(rules, &(a.Rules[id]))
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
		rule := rules[0]
		rule.Value = fmt.Sprintf("%v;%v", rule.Value, value)
	}
}

func (a *Application) RemoveRule(rule *ApplicationRule) {
	for i := 0; i < len(a.Rules); i++ {
		if rule == &a.Rules[i] {
			a.Rules = append(a.Rules[:i], a.Rules[i+1:]...)
			return
		}
	}
}

// AssignProject will create or update a "project.name.in" type rule to assign the project to the app
func (a *Application) AssignProject(project *Project) {
	a.AddRule("project.name.in", project.Name)
}

// UnassignProject will remove the project from the "project.name.in" rule if it's there, and if the rule ends up empty it will remove the rule
func (a *Application) UnassignProject(project *Project) {
	rules := a.GetRulesByType("project.name.in")
	if len(rules) == 0 {
		return
	}

	for _, rule := range rules {
		if strings.Contains(fmt.Sprintf(";%v;", rule.Value), fmt.Sprintf(";%v;", project.Name)) {
			rule.RemoveItem(project.Name)
			if rule.Value == "" {
				a.RemoveRule(rule)
			}
			return // rule value already contains this value
		}
	}
}

func (ar *ApplicationRule) RemoveItem(item string) {
	rulestr := ";" + ar.Value + ";"
	itemstr := ";" + item + ";"
	if strings.Contains(rulestr, item) {
		rulestr = strings.Replace(rulestr, itemstr, ";", 1)
		rulestr = rulestr[1:] // chop out starting ;
		if len(rulestr) > 0 {
			rulestr = rulestr[:len(rulestr)-1]
		}
	}
	ar.Value = rulestr
}
