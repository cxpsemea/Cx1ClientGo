package Cx1ClientGo

import (
	"fmt"
	"strings"
)

type Cx1Cache struct {
	ProjectRefresh     bool
	Projects           []Project
	GroupRefresh       bool
	Groups             []Group
	UserRefresh        bool
	Users              []User
	QueryRefresh       bool
	Queries            SASTQueryCollection
	PresetRefresh      bool
	Presets            map[string][]Preset
	RoleRefresh        bool
	Roles              []Role
	Applications       []Application
	ApplicationRefresh bool
	Clients            []OIDCClient
	ClientRefresh      bool
}

func (c *Cx1Cache) PresetSummary() string {
	return fmt.Sprintf("%d presets", len(c.Presets))
}

func (c *Cx1Cache) QuerySummary() string {
	return fmt.Sprintf("%d languages", len(c.Queries.QueryLanguages))
}
func (c *Cx1Cache) UserSummary() string {
	return fmt.Sprintf("%d users", len(c.Users))
}
func (c *Cx1Cache) GroupSummary() string {
	return fmt.Sprintf("%d groups", len(c.Groups))
}
func (c *Cx1Cache) ProjectSummary() string {
	return fmt.Sprintf("%d projects", len(c.Projects))
}
func (c *Cx1Cache) ApplicationSummary() string {
	return fmt.Sprintf("%d applications", len(c.Applications))
}
func (c *Cx1Cache) ClientSummary() string {
	return fmt.Sprintf("%d clients", len(c.Clients))
}

func (c *Cx1Cache) RefreshProjects(client *Cx1Client) error {
	////client.logger.Infof("Refreshing projects in Cx1 cache")
	var err error
	if !c.ProjectRefresh {
		c.ProjectRefresh = true
		c.Projects, err = client.GetAllProjects()
		c.ProjectRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshApplications(client *Cx1Client) error {
	////client.logger.Infof("Refreshing applications in Cx1 cache")
	var err error
	if !c.ApplicationRefresh {
		c.ApplicationRefresh = true
		c.Applications, err = client.GetAllApplications()
		c.ApplicationRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshClients(client *Cx1Client) error {
	////client.logger.Infof("Refreshing OIDC Clients in Cx1 cache")
	var err error
	if !c.ClientRefresh {
		c.ClientRefresh = true
		c.Clients, err = client.GetClients()
		c.ClientRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshGroups(client *Cx1Client) error {
	////client.logger.Infof("Refreshing groups in Cx1 cache")
	var err error
	if !c.GroupRefresh {
		c.GroupRefresh = true
		c.Groups, err = client.GetGroups()
		c.GroupRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshUsers(client *Cx1Client) error {
	////client.logger.Infof("Refreshing users in Cx1 cache")
	var err error
	if !c.UserRefresh {
		c.UserRefresh = true
		c.Users, err = client.GetAllUsers()
		c.UserRefresh = false
	}
	return err
}

// This is only the SAST queries
// To do - add IAC?
func (c *Cx1Cache) RefreshQueries(client *Cx1Client) error {
	//client.logger.Infof("Refreshing queries in Cx1 cache")
	var err error
	if !c.QueryRefresh {
		c.QueryRefresh = true
		c.Queries, err = client.GetSASTQueryCollection()
		c.QueryRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshPresets(client *Cx1Client) error {
	//client.logger.Infof("Refreshing presets in Cx1 cache")
	var err error
	if !c.PresetRefresh {
		c.PresetRefresh = true
		if c.Presets == nil {
			c.Presets = make(map[string][]Preset)
		}
		var presets []Preset
		presets, err = client.GetAllSASTPresets()

		if err != nil {
			//client.logger.Tracef("Failed while retrieving presets: %s", err)
		} else {
			for id := range presets {
				err := client.GetPresetContents(&presets[id])
				if err != nil {
					//client.logger.Tracef("Failed to retrieve preset contents for preset %v: %s", presets[id].String(), err)
				}
			}
		}
		c.Presets["sast"] = presets

		presets, err = client.GetAllIACPresets()

		if err != nil {
			//client.logger.Tracef("Failed while retrieving presets: %s", err)
		} else {
			for id := range presets {
				err := client.GetPresetContents(&presets[id])
				if err != nil {
					//client.logger.Tracef("Failed to retrieve preset contents for preset %v: %s", presets[id].String(), err)
				}
			}
		}
		c.Presets["iac"] = presets

		c.PresetRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshRoles(client *Cx1Client) error {
	//client.logger.Infof("Refreshing roles in Cx1 cache")
	var err error
	if !c.RoleRefresh {
		c.RoleRefresh = true
		c.Roles, err = client.GetRoles()
		if err != nil {
			//client.logger.Tracef("Failed while retrieving roles: %s", err)
		} else {
			for id, r := range c.Roles {
				var role Role
				var err error
				if r.ClientRole {
					role, err = client.GetAppRoleByName(r.Name)
				}
				c.Roles[id].Attributes = role.Attributes
				if err != nil {
					//client.logger.Tracef("Failed to retrieve details for role %v: %s", r.String(), err)
				}
			}
		}
		c.RoleRefresh = false
	}
	return err
}

func (c *Cx1Cache) Refresh(client *Cx1Client) []error {
	var errs []error

	if err := c.RefreshProjects(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshApplications(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshGroups(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshUsers(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshQueries(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshPresets(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshRoles(client); err != nil {
		errs = append(errs, err)
	}

	if err := c.RefreshClients(client); err != nil {
		errs = append(errs, err)
	}

	c.MatchPresetQueries()

	return errs
}

func (c *Cx1Cache) MatchPresetQueries() {
	if _, ok := c.Presets["sast"]; ok {
		for id := range c.Presets["sast"] {
			p := c.Presets["sast"][id]
			//p.LinkQueries(&c.Queries)
			c.Presets["sast"][id] = p
		}
	}
}

func (c *Cx1Cache) GetGroup(groupID string) (*Group, error) {
	for id, t := range c.Groups {
		if strings.EqualFold(t.GroupID, groupID) {
			return &c.Groups[id], nil
		}
	}
	return nil, fmt.Errorf("no such group %v", groupID)
}
func (c *Cx1Cache) GetGroupByName(name string) (*Group, error) {
	for id, t := range c.Groups {
		if strings.EqualFold(t.Name, name) {
			return &c.Groups[id], nil
		}
	}
	return nil, fmt.Errorf("no such group %v", name)
}

func (c *Cx1Cache) GetUser(userID string) (*User, error) {
	for id, g := range c.Users {
		if strings.EqualFold(g.UserID, userID) {
			return &c.Users[id], nil
		}
	}
	return nil, fmt.Errorf("no such user %v", userID)
}
func (c *Cx1Cache) GetUserByEmail(email string) (*User, error) {
	for id, g := range c.Users {
		if strings.EqualFold(g.Email, email) {
			return &c.Users[id], nil
		}
	}
	return nil, fmt.Errorf("no such user %v", email)
}
func (c *Cx1Cache) GetUserByString(displaystring string) (*User, error) {
	for id, g := range c.Users {
		if strings.EqualFold(g.String(), displaystring) {
			return &c.Users[id], nil
		}
	}
	return nil, fmt.Errorf("no such user %v", displaystring)
}

func (c *Cx1Cache) GetProject(projectID string) (*Project, error) {
	for id, g := range c.Projects {
		if strings.EqualFold(g.ProjectID, projectID) {
			return &c.Projects[id], nil
		}
	}
	return nil, fmt.Errorf("no such project %v", projectID)
}
func (c *Cx1Cache) GetProjectByName(name string) (*Project, error) {
	for id, g := range c.Projects {
		if strings.EqualFold(g.Name, name) {
			return &c.Projects[id], nil
		}
	}
	return nil, fmt.Errorf("no such project %v", name)
}

func (c *Cx1Cache) GetApplication(applicationID string) (*Application, error) {
	for id, g := range c.Applications {
		if strings.EqualFold(g.ApplicationID, applicationID) {
			return &c.Applications[id], nil
		}
	}
	return nil, fmt.Errorf("no such application %v", applicationID)
}
func (c *Cx1Cache) GetApplicationByName(name string) (*Application, error) {
	for id, g := range c.Applications {
		if strings.EqualFold(g.Name, name) {
			return &c.Applications[id], nil
		}
	}
	return nil, fmt.Errorf("no such application %v", name)
}

func (c *Cx1Cache) GetClient(ID string) (*OIDCClient, error) {
	for id, cli := range c.Clients {
		if strings.EqualFold(cli.ID, ID) {
			return &c.Clients[id], nil
		}
	}
	return nil, fmt.Errorf("no such Client %v", ID)
}
func (c *Cx1Cache) GetClientByID(clientId string) (*OIDCClient, error) {
	for id, cli := range c.Clients {
		if strings.EqualFold(cli.ClientID, clientId) {
			return &c.Clients[id], nil
		}
	}
	return nil, fmt.Errorf("no such Client %v", clientId)
}

func (c *Cx1Cache) GetPreset(engine string, presetID string) (*Preset, error) {
	for id, g := range c.Presets[engine] {
		if g.PresetID == presetID {
			return &c.Presets[engine][id], nil
		}
	}
	return nil, fmt.Errorf("no such preset %v", presetID)
}
func (c *Cx1Cache) GetPresetByName(engine, name string) (*Preset, error) {
	for id, g := range c.Presets[engine] {
		if strings.EqualFold(g.Name, name) {
			return &c.Presets[engine][id], nil
		}
	}
	return nil, fmt.Errorf("no such preset %v", name)
}

func (c *Cx1Cache) GetRole(roleID string) (*Role, error) {
	for id, g := range c.Roles {
		if strings.EqualFold(g.RoleID, roleID) {
			return &c.Roles[id], nil
		}
	}
	return nil, fmt.Errorf("no such role %v", roleID)
}
func (c *Cx1Cache) GetRoleByName(name string) (*Role, error) {
	for id, g := range c.Roles {
		if strings.EqualFold(g.Name, name) {
			return &c.Roles[id], nil
		}
	}
	return nil, fmt.Errorf("no such role %v", name)
}

func (c *Cx1Cache) GetQuery(queryID uint64) (*SASTQuery, error) {
	q := c.Queries.GetQueryByID(queryID)
	if q != nil {
		return q, nil
	}
	return nil, fmt.Errorf("no such query %d", queryID)
}
func (c *Cx1Cache) GetQueryByNames(language, group, query string) (*SASTQuery, error) {
	ql := c.Queries.GetQueryLanguageByName(language)
	if ql == nil {
		return nil, fmt.Errorf("no such language %v", language)
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil, fmt.Errorf("no such group %v", group)
	}
	q := qg.GetQueryByName(query)
	if q == nil {
		return nil, fmt.Errorf("no such query %v", query)
	}
	return q, nil
}
