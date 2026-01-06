package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/exp/slices"
)

func (r Role) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(r.RoleID), r.Name)
}

func (r Role) HasCategory(name string) bool {
	for _, role := range r.Attributes.Category {
		if role == name {
			return true
		}
	}
	return false
}

func (r Role) HasRole(name string) bool {
	for _, r := range r.SubRoles {
		if r.Name == name {
			return true
		}
	}
	return false
}

func (c *Cx1Client) GetIAMRoles() ([]Role, error) {
	c.config.Logger.Debugf("Getting KeyCloak Roles")
	var roles []Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/roles?briefRepresentation=true", nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	c.config.Logger.Tracef("Got %d roles", len(roles))
	return roles, err
}

func (c *Cx1Client) GetIAMRoleByName(name string) (Role, error) {
	c.config.Logger.Debugf("Getting KeyCloak Role named %v", name)
	var role Role
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/roles/%v", url.QueryEscape(name)), nil, nil)
	if err != nil {
		return role, err
	}

	err = json.Unmarshal(response, &role)
	return role, err
}

func (c *Cx1Client) GetIAMRolesByName(name string) ([]Role, error) {
	c.config.Logger.Debugf("Getting KeyCloak Roles with name matching %v", name)
	var roles []Role
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/roles/?search=%v&briefRepresentation=false", url.QueryEscape(name)), nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	return roles, err
}

func (c *Cx1Client) GetRolesByClientID(clientId string) ([]Role, error) {
	c.config.Logger.Debugf("Getting roles for client %v", clientId)
	var roles []Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/roles?briefRepresentation=true", clientId), nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	c.config.Logger.Tracef("Got %d roles", len(roles))
	return roles, err
}

func (c *Cx1Client) GetRoleByClientIDAndName(clientId string, name string) (Role, error) {
	c.config.Logger.Debugf("Getting KeyCloak Roles for client %v with name %v", clientId, name)
	var role Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/roles/%v", clientId, url.PathEscape(name)), nil, nil)
	if err != nil {
		return role, err
	}

	err = json.Unmarshal(response, &role)
	return role, err
}

func (c *Cx1Client) GetRolesByClientIDAndName(clientId string, name string) ([]Role, error) {
	c.config.Logger.Debugf("Getting KeyCloak Roles for client %v with name matching %v", clientId, name)
	var roles []Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/roles?search=%v&briefRepresentation=false", clientId, url.PathEscape(name)), nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	return roles, err
}

// returns all sub-roles assigned to a specific composite role, including nested composites
func (c *Cx1Client) GetAllRoleComposites(role *Role) ([]Role, error) {
	c.config.Logger.Debugf("Getting all composites for role %v", role.String())
	var all_roles []Role
	var role_ids []string

	roles, err := c.GetRoleComposites(role)
	if err != nil {
		return []Role{}, err
	}

	for _, r := range roles {
		if !slices.Contains(role_ids, r.RoleID) {
			if r.Composite {
				subroles, err := c.GetAllRoleComposites(&r)
				if err != nil {
					return []Role{}, err
				}

				for _, sr := range subroles {
					if !slices.Contains(role_ids, sr.RoleID) {
						role_ids = append(role_ids, sr.RoleID)
						all_roles = append(all_roles, sr)
					}
				}
			}
			role_ids = append(role_ids, r.RoleID)
			all_roles = append(all_roles, r)
		}
	}

	return all_roles, nil
}

// returns the sub-roles assigned to a specific composite role and also fills role.SubRoles
func (c *Cx1Client) GetRoleComposites(role *Role) ([]Role, error) {
	var roles []Role
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/roles-by-id/%v/composites", role.RoleID), nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	if err != nil {
		return roles, err
	}

	role.SubRoles = roles
	return roles, nil
}

func (c *Cx1Client) AddRoleComposites(role *Role, roles *[]Role) error {
	if len(*roles) == 0 {
		return fmt.Errorf("no role IDs provided")
	}

	roleList := make([]struct {
		ID string `json:"id"`
	}, len(*roles))

	for id, role := range *roles {
		roleList[id].ID = role.RoleID
	}

	jsonBody, _ := json.Marshal(roleList)
	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/roles-by-id/%v/composites", role.RoleID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cx1Client) RemoveRoleComposites(role *Role, roles *[]Role) error {
	if len(*roles) == 0 {
		return fmt.Errorf("no role IDs provided")
	}

	roleList := make([]struct {
		ID string `json:"id"`
	}, len(*roles))
	for id, role := range *roles {
		roleList[id].ID = role.RoleID
	}

	jsonBody, _ := json.Marshal(roleList)
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/roles-by-id/%v/composites", role.RoleID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cx1Client) CreateAppRole(roleName, createdBy string) (Role, error) {
	c.config.Logger.Debugf("User %v creating client role %v", createdBy, roleName)
	data := map[string]interface{}{
		"name":       roleName,
		"composite":  true,
		"clientRole": true,
		"attributes": map[string]interface{}{
			"category":   []string{"Composite role"},
			"type":       []string{"Role"},
			"creator":    []string{fmt.Sprintf("%v", createdBy)},
			"lastUpdate": []int64{time.Now().UnixMilli()},
		},
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		c.config.Logger.Tracef("Failed to marshal data somehow: %s", err)
		return Role{}, err
	}
	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/clients/%v/roles", c.GetASTAppID()), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.config.Logger.Tracef("Failed to create a client role %v: %s", roleName, err)
		return Role{}, err
	}

	return c.GetRoleByClientIDAndName(c.GetASTAppID(), roleName)
}

// roles are returned without sub-roles, use GetRoleComposites(&role) to fill
func (c *Cx1Client) GetRoleByID(roleId string) (Role, error) {
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/roles-by-id/%v", roleId), nil, nil)
	var role Role
	if err != nil {
		return role, err
	}

	err = json.Unmarshal(response, &role)
	return role, err
}

func (c *Cx1Client) DeleteRoleByID(roleId string) error {
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/roles-by-id/%v", roleId), nil, nil)
	return err
}

func (c *Cx1Client) GetAppRoles() ([]Role, error) {
	c.config.Logger.Debugf("Getting roles set for ast-app client")
	return c.GetRolesByClientID(c.GetASTAppID())
}

func (c *Cx1Client) GetAppRoleByName(name string) (Role, error) {
	c.config.Logger.Debugf("Getting role named %v in ast-app client", name)
	return c.GetRoleByClientIDAndName(c.GetASTAppID(), name)
}

func (c *Cx1Client) GetAppRolesByName(name string) ([]Role, error) {
	c.config.Logger.Debugf("Getting roles matching %v in ast-app client", name)
	return c.GetRolesByClientIDAndName(c.GetASTAppID(), name)
}

// convenience function to get both KeyCloak (system) roles plus the AST-APP-specific roles
// roles are returned without sub-roles, use GetRoleComposites(&role) to fill
func (c *Cx1Client) GetRoles() ([]Role, error) {
	c.config.Logger.Debugf("Getting all available roles")
	ast_roles, err := c.GetAppRoles()
	if err != nil {
		return ast_roles, err
	}
	system_roles, err := c.GetIAMRoles()
	if err != nil {
		return ast_roles, err
	}

	ast_roles = append(ast_roles, system_roles...)
	return ast_roles, nil
}

// roles are returned without sub-roles, use GetRoleComposites(&role) to fill
func (c *Cx1Client) GetRoleByName(name string) (Role, error) {
	c.config.Logger.Debugf("Getting any role named: %v", name)

	role, err := c.GetAppRoleByName(name)
	if err == nil {
		return role, nil
	}
	role, err = c.GetIAMRoleByName(name)
	if err == nil {
		return role, nil
	}

	return Role{}, fmt.Errorf("Role %v not found", name)
}

// roles are returned without sub-roles, use GetRoleComposites(&role) to fill
func (c *Cx1Client) GetRolesByName(name string) ([]Role, error) {
	c.config.Logger.Debugf("Getting any roles matching %v", name)
	var all_roles []Role
	roles, err := c.GetAppRolesByName(name)
	if err != nil {
		return all_roles, err
	}
	all_roles = append(all_roles, roles...)

	roles, err = c.GetIAMRolesByName(name)
	if err != nil {
		return all_roles, err
	}
	all_roles = append(all_roles, roles...)

	return all_roles, nil
}

func (c *Cx1Client) RoleLink(r *Role) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/roles/%v", c.config.IAMUrl, c.config.Tenant, c.config.Tenant, r.RoleID)
}
