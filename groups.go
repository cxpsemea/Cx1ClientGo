package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
)

func (g Group) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(g.GroupID), g.Name)
}

// create a top-level group
func (c *Cx1Client) CreateGroup(groupname string) (Group, error) {
	c.config.Logger.Debugf("Create Group: %v ", groupname)
	data := map[string]interface{}{
		"name": groupname,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Group{}, err
	}

	response, err := c.sendRequestRawIAM(http.MethodPost, "/auth/admin", "/groups", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.config.Logger.Tracef("Error creating group %v: %s", groupname, err)
		return Group{}, err
	}

	location := response.Header.Get("Location")
	if location != "" {
		lastInd := strings.LastIndex(location, "/")
		guid := location[lastInd+1:]
		c.config.Logger.Tracef("New group ID: %v", guid)
		return c.GetGroupByID(guid)
	} else {
		return Group{}, fmt.Errorf("unknown error - no Location header redirect in response")
	}
}

func (c *Cx1Client) CreateChildGroup(parentGroup *Group, childGroupName string) (Group, error) {
	c.config.Logger.Debugf("Create child Group: %v ", childGroupName)
	var child_group Group
	data := map[string]interface{}{
		"name": childGroupName,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return child_group, err
	}

	response, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups/"+parentGroup.GroupID+"/children", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.config.Logger.Errorf("Error creating group: %s", err)
		return child_group, err
	}

	err = json.Unmarshal(response, &child_group)
	if err != nil {
		c.config.Logger.Errorf("Error unmarshalling new child group: %s", err)
		return child_group, err
	}

	parentGroup.SubGroups = append(parentGroup.SubGroups, child_group)

	return child_group, err
}

func (c *Cx1Client) GetGroupsPIP() ([]Group, error) {
	c.config.Logger.Debugf("Get cx1 groups pip")
	var groups []Group
	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/pip/groups", nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	return groups, err
}

func (c *Cx1Client) GetGroupPIPByName(groupname string) (Group, error) {
	c.config.Logger.Debugf("Get Cx1 Group by name: %v", groupname)

	groups, err := c.GetGroupsPIP()
	if err != nil {
		return Group{}, err
	}

	for _, g := range groups {
		if g.Name == groupname {
			return g, nil
		}
	}

	return Group{}, fmt.Errorf("no such group %v found", groupname)
}

// this returns all groups including all subgroups
func (c *Cx1Client) GetGroups() ([]Group, error) {
	c.config.Logger.Debugf("Get Cx1 Groups")
	_, groups, err := c.GetAllGroupsFiltered(GroupFilter{
		BriefRepresentation: boolPtr(false),
		PopulateHierarchy:   boolPtr(false),
		BaseIAMFilter:       BaseIAMFilter{Max: c.config.Pagination.Groups},
	}, true)
	return groups, err
}

func (c *Cx1Client) GetAllGroups() ([]Group, error) {
	return c.GetGroups()
}

// will return the first group matching 'groupname'
// the group is not "filled": the subgroups array will be empty (use FillGroup/GetGroupChildren)
func (c *Cx1Client) GetGroupByName(groupname string) (Group, error) {
	c.config.Logger.Debugf("Get Cx1 Group by name: %v", groupname)
	_, groups, err := c.GetAllGroupsFiltered(GroupFilter{
		BriefRepresentation: boolPtr(false),
		PopulateHierarchy:   boolPtr(false),
		Search:              groupname,
		Exact:               boolPtr(true),
		BaseIAMFilter:       BaseIAMFilter{Max: c.config.Pagination.Groups},
	}, false)

	if err != nil {
		return Group{}, err
	}

	c.config.Logger.Tracef("Got %d groups", len(groups))

	for i := range groups {
		if check, _ := c.version.CheckCxOne("3.20.0"); check >= 0 {
			setGroupFilled(&groups[i])
		}

		if groups[i].Name == groupname {
			return groups[i], nil
		} else if g, err := groups[i].FindSubgroupByName(groupname); err == nil {
			return g, nil
		}
	}

	return Group{}, fmt.Errorf("no group %v found", groupname)
}

// this function returns all top-level groups matching the search string, or
// if a sub-group matches the search, it will return the parent group and only the matching subgroups
// the returned groups are not "filled": they will not include subgroups that do not match the search term
func (c *Cx1Client) GetGroupsByName(groupname string) ([]Group, error) {
	c.config.Logger.Debugf("Get Cx1 Groups by name: %v", groupname)
	_, groups, err := c.GetAllGroupsFiltered(GroupFilter{
		BriefRepresentation: boolPtr(false),
		PopulateHierarchy:   boolPtr(true),
		Search:              groupname,
		BaseIAMFilter:       BaseIAMFilter{Max: c.config.Pagination.Groups},
	}, false)

	return groups, err
}

func (c *Cx1Client) GetGroupCount(search string, topLevel bool) (uint64, error) {
	c.config.Logger.Debugf("Get Cx1 Group count with search=%v, topLevel=%v", search, topLevel)

	params := url.Values{}

	if search != "" {
		params.Add("search", search)
	}
	if topLevel {
		params.Add("top", "true")
	}

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/count?%v", params.Encode()), nil, nil)
	if err != nil {
		return 0, err
	}

	var CountResponse struct {
		Count uint64 `json:"count"`
	}

	err = json.Unmarshal(response, &CountResponse)
	return CountResponse.Count, err
}

// Underlying function used by many GetGroups* calls
// Returns the number of applications matching the filter and the array of matching applications
func (c *Cx1Client) GetGroupsFiltered(filter GroupFilter, fill bool) ([]Group, error) {
	var groups []Group
	params, _ := query.Values(filter)

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups?%v", params.Encode()), nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	if err != nil {
		return groups, err
	}

	if fill {
		for i := range groups {
			c.FillGroup(&groups[i])
		}
	}

	return groups, err
}

// returns all groups matching the filter
// fill parameter will recursively fill subgroups
func (c *Cx1Client) GetAllGroupsFiltered(filter GroupFilter, fill bool) (uint64, []Group, error) {
	var groups []Group

	count, err := c.GetGroupCount(filter.Search, true)
	if err != nil {
		return count, groups, err
	}
	gs, err := c.GetGroupsFiltered(filter, fill)
	groups = gs

	for err == nil && count > filter.Max+filter.First && filter.Max > 0 {
		filter.Bump()
		gs, err = c.GetGroupsFiltered(filter, fill)
		groups = append(groups, gs...)
	}

	return count, groups, err
}

func (c *Cx1Client) DeleteGroup(group *Group) error {
	c.config.Logger.Debugf("Deleting Group %v...", group.String())
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v", group.GroupID), nil, http.Header{})
	return err
}

// this will return the specific group matching this ID
func (c *Cx1Client) GetGroupByID(groupID string) (Group, error) {
	c.config.Logger.Debugf("Getting Group with ID %v...", groupID)
	var group Group

	body := url.Values{
		"briefRepresentation": {"false"}, // ensure the group includes roles
	}

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v?%v", groupID, body.Encode()), nil, http.Header{})
	if err != nil {
		c.config.Logger.Tracef("Fetching group %v failed: %s", groupID, err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	if err != nil {
		return group, err
	}

	if check, _ := c.version.CheckCxOne("3.20.0"); check == -1 { // old version API included the subgroups&roles in this call
		group.Filled = true
	} else { // new version includes the roles but not subgroups
		_, err = c.GetGroupChildren(&group)
	}
	return group, err
}

// this function is for CxOne v3.20+
// gets and fills the group's immediate children (subgroups)
// does not include sub-children
func (c *Cx1Client) GetGroupChildren(group *Group) ([]Group, error) {
	var groups []Group
	if group.SubGroupCount == 0 && group.Filled { // add the .filled check as a double-check that the 0-subgroupcount is valid
		return groups, nil
	}

	var err error
	group.SubGroups = []Group{}
	for offset := uint64(0); offset < group.SubGroupCount; offset += c.config.Pagination.Groups {
		groups, err = c.GetGroupChildrenByID(group.GroupID, offset, c.config.Pagination.Groups)
		if err != nil {
			return group.SubGroups, err
		}
		group.SubGroups = append(group.SubGroups, groups...)
	}

	group.Filled = true
	return group.SubGroups, nil
}

// fills the group's immediate children (subgroups) along with sub-children and all descendents
func (c *Cx1Client) FillGroup(group *Group) error {
	if group.SubGroupCount != uint64(len(group.SubGroups)) {
		if _, err := c.GetGroupChildren(group); err != nil {
			return err
		}
	} else {
		group.Filled = true
	}

	group.DescendentCount = group.SubGroupCount

	for i := range group.SubGroups {
		if err := c.FillGroup(&group.SubGroups[i]); err != nil {
			return err
		}

		group.DescendentCount += group.SubGroups[i].DescendentCount
	}
	return nil
}

// this function is for CxOne v3.20+
// Used by GetGroupChildren
func (c *Cx1Client) GetGroupChildrenByID(groupID string, first, max uint64) ([]Group, error) {
	var groups []Group
	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v/children?briefRepresentation=false&first=%d&max=%d", groupID, first, max), nil, http.Header{})
	if err != nil {
		c.config.Logger.Tracef("Fetching group %v children failed: %s", groupID, err)
		return groups, err
	}

	err = json.Unmarshal(data, &groups)
	return groups, err
}

// this returns all roles a user would inherit from membership in this group
// this includes the roles assigned directly to the group (group.RealmRoles & group.ClientRoles)
// as well as the roles from up the group hierarchy
// this function expects a group retrieved by a GetGroup* call, user-groups returned from a GetUser* call do not include role information.
func (c *Cx1Client) GetGroupInheritedRoles(group *Group) (roles []Role, err error) {
	// get all roles for this group
	// go up the group hierarchy
	c.config.Logger.Debugf("Get group inherited roles for group %v", group.String())
	realmRoleList, clientRoleList, err := c.getGroupInheritedRoleStrings(group)
	if err != nil {
		return nil, err
	}

	realmRoles, clientRoles, err := c.resolveRealmAndClientRoleLists(&realmRoleList, &clientRoleList)
	roles = append(realmRoles, clientRoles...)
	return roles, err
}

func (c *Cx1Client) getGroupInheritedRoleStrings(group *Group) (realmRoleList []string, clientRoleList map[string][]string, err error) {
	realmRoles := make(map[string]struct{})
	clientRoles := make(map[string]map[string]struct{})

	if version, err := c.CheckIAMVersion(); err != nil {
		return nil, nil, err
	} else if version >= 2 {
		c.config.Logger.Debugf("Users globally inherit roles from group membership only in old-IAM and IAM Phase1, this tenant is IAM Phase2")
		return nil, nil, nil
	}

	for _, rr := range group.RealmRoles {
		realmRoles[rr] = struct{}{}
	}
	for client, crlist := range group.ClientRoles {
		if _, ok := clientRoles[client]; !ok {
			clientRoles[client] = make(map[string]struct{})
		}
		for _, cr := range crlist {
			clientRoles[client][cr] = struct{}{}
		}
	}

	if group.ParentID != "" {
		parentGroup, err := c.GetGroupByID(group.ParentID)
		if err != nil {
			return nil, nil, err
		}

		parentRealmRoles, parentClientRoles, err := c.getGroupInheritedRoleStrings(&parentGroup)
		if err != nil {
			return nil, nil, err
		}

		for _, rr := range parentRealmRoles {
			realmRoles[rr] = struct{}{}
		}
		for client, crlist := range parentClientRoles {
			if _, ok := clientRoles[client]; !ok {
				clientRoles[client] = make(map[string]struct{})
			}
			for _, cr := range crlist {
				clientRoles[client][cr] = struct{}{}
			}
		}
	}

	realmRoleList = []string{}
	for rr := range realmRoles {
		realmRoleList = append(realmRoleList, rr)
	}
	clientRoleList = make(map[string][]string)
	for client, crlist := range clientRoles {
		clientRoleList[client] = []string{}
		for cr := range crlist {
			clientRoleList[client] = append(clientRoleList[client], cr)
		}
	}

	return realmRoleList, clientRoleList, nil
}

// this function returns a group matching a path, however as of keycloak 23.0.7 this endpoint
// is missing the subGroupCount field, which other parts of cx1clientgo rely on, so this function
// will automatically trigger a GetGroupByID call
func (c *Cx1Client) GetGroupByPath(path string) (Group, error) {
	c.config.Logger.Debugf("Getting Group with path %v...", path)
	var group Group
	if path[:1] == "/" {
		path = path[1:]
	}

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/group-by-path/%v", path), nil, http.Header{})
	if err != nil {
		c.config.Logger.Tracef("Fetching group %v failed: %s", path, err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	if err != nil {
		return group, err
	}
	return c.GetGroupByID(group.GroupID)
}

func (c *Cx1Client) GroupLink(g *Group) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/groups/%v", c.config.IamUrl, c.config.Tenant, c.config.Tenant, g.GroupID)
}

// Sets group g as child of group parent
// If parent == nil, sets the group as top-level
func (c *Cx1Client) SetGroupParent(g *Group, parent *Group) error {
	body := map[string]string{
		"id":   g.GroupID,
		"name": g.Name,
	}
	jsonBody, _ := json.Marshal(body)
	if parent != nil {
		_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/children", parent.GroupID), bytes.NewReader(jsonBody), http.Header{})
		if err != nil {
			c.config.Logger.Tracef("Failed to add child to parent: %s", err)
			return err
		}
	} else {
		_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups", bytes.NewReader(jsonBody), http.Header{})
		if err != nil {
			c.config.Logger.Tracef("Failed to move group to top-level: %s", err)
			return err
		}
	}

	return nil
}

func (c *Cx1Client) UpdateGroup(g *Group) error {
	if !g.Filled {
		if check, _ := c.version.CheckCxOne("3.20.0"); check >= 0 {
			return fmt.Errorf("group %v data is not filled (use GetGroupChildren) - may be missing expected roles & subgroups, update aborted", g.String())
		} else {
			return fmt.Errorf("group %v data is not filled (use GetGroupByID) - may be missing expected roles & subgroups, update aborted", g.String())
		}
	}

	err := c.groupRoleChange(g)
	if err != nil {
		return fmt.Errorf("failed to update role changes for group %v: %s", g.String(), err)
	}

	jsonBody, _ := json.Marshal(*g)
	_, err = c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/groups/%v", g.GroupID), bytes.NewReader(jsonBody), http.Header{})
	return err
}

func (g *Group) AddRole(clientName, roleName string) error {
	if !g.Filled {
		return fmt.Errorf("group is not filled, first fetch the details via GetGroupByID")
	}

	if g.ClientRoles == nil {
		g.ClientRoles = make(map[string][]string)
	}

	_, ok := g.ClientRoles[clientName]
	if !ok {
		g.ClientRoles[clientName] = make([]string, 0)
	}

	for _, role := range g.ClientRoles[clientName] {
		if strings.EqualFold(role, roleName) {
			return fmt.Errorf("group already has role %v - %v", clientName, roleName)
		}
	}

	g.ClientRoles[clientName] = append(g.ClientRoles[clientName], roleName)

	return nil
}

func (g *Group) RemoveRole(clientName, roleName string) error {
	if !g.Filled {
		return fmt.Errorf("group %v is not filled, first fetch the details via GetGroupByID", g.String())
	}

	_, ok := g.ClientRoles[clientName]
	if !ok {
		return fmt.Errorf("group %v does not have the %v client", g.String(), clientName)
	}

	for id, role := range g.ClientRoles[clientName] {
		if strings.EqualFold(role, roleName) {
			return fmt.Errorf("group already has role %v - %v", clientName, roleName)
		} else {
			if id != len(g.ClientRoles[clientName])-1 {
				g.ClientRoles[clientName][id] = g.ClientRoles[clientName][len(g.ClientRoles[clientName])-1]
			}
			g.ClientRoles[clientName] = g.ClientRoles[clientName][:len(g.ClientRoles[clientName])-1]
			return nil
		}
	}

	return fmt.Errorf("group %v does not have the %v - %v role", g.String(), clientName, roleName)
}

func (c *Cx1Client) groupRoleChange(g *Group) error {
	orig_group, err := c.GetGroupByID(g.GroupID)
	if err != nil {
		return fmt.Errorf("failed to get original group info for group %v: %s", g.String(), err)
	}

	add_roles := map[string][]string{}
	del_roles := map[string][]string{}

	for new_client, new_roles := range g.ClientRoles {
		if _, ok := orig_group.ClientRoles[new_client]; !ok {
			add_roles[new_client] = new_roles
		} else {
			for _, nr := range new_roles {
				found := false
				for _, or := range orig_group.ClientRoles[new_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					add_roles[new_client] = append(add_roles[new_client], nr)
				}
			}
		}
	}

	for orig_client, orig_roles := range orig_group.ClientRoles {
		if _, ok := g.ClientRoles[orig_client]; !ok {
			del_roles[orig_client] = orig_roles
		} else {
			for _, nr := range orig_roles {
				found := false
				for _, or := range g.ClientRoles[orig_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					del_roles[orig_client] = append(del_roles[orig_client], nr)
				}
			}
		}
	}

	if len(del_roles) > 0 {
		err = c.DeleteRolesFromGroup(g, del_roles)
		if err != nil {
			return fmt.Errorf("failed to delete roles from group %v: %s", g.String(), err)
		}
	}

	if len(add_roles) > 0 {
		err = c.AddRolesToGroup(g, add_roles)
		if err != nil {
			return fmt.Errorf("failed to add roles to group %v: %s", g.String(), err)
		}
	}

	return nil
}

/*
clientRoles map looks like: "ast-app" : { "ast-scanner", "ast-viewer" }
*/
func (c *Cx1Client) DeleteRolesFromGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClientID(kc_client.ID)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		if len(role_list) > 0 {
			jsonBody, _ := json.Marshal(role_list)
			_, err = c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ID), bytes.NewReader(jsonBody), http.Header{})
			if err != nil {
				return fmt.Errorf("failed to remove roles from group %v: %s", g.String(), err)
			}
		} else {
			c.config.Logger.Warnf("DeleteRolesFromGroup called but there are no roles to delete")
		}
	}

	return nil
}

/*
clientRoles map looks like: "ast-app" : { "ast-scanner", "ast-viewer" }
*/
func (c *Cx1Client) AddRolesToGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClientID(kc_client.ID) // all roles in keycloak/iam
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		if len(role_list) > 0 {
			jsonBody, _ := json.Marshal(role_list)
			_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ID), bytes.NewReader(jsonBody), http.Header{})
			if err != nil {
				return fmt.Errorf("failed to add roles to group %v: %s", g.String(), err)
			}
		} else {
			c.config.Logger.Warnf("AddRolesToGroup called but there are no roles to add")
		}
	}

	return nil
}

func (c *Cx1Client) GetGroupMembers(group *Group) ([]User, error) {
	return c.GetGroupMembersByID(group.GroupID)
}

func (c *Cx1Client) GetGroupMembersByID(groupId string) ([]User, error) {
	_, users, err := c.GetAllGroupMembersFiltered(groupId, GroupMembersFilter{
		BaseIAMFilter: BaseIAMFilter{Max: c.config.Pagination.GroupMembers},
	})
	return users, err
}

func (c *Cx1Client) GetGroupMembersFiltered(groupId string, filter GroupMembersFilter) ([]User, error) {
	var members []User
	params, _ := query.Values(filter)

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v/members?%v", groupId, params.Encode()), nil, nil)
	if err != nil {
		return members, err
	}

	err = json.Unmarshal(response, &members)
	if err != nil {
		return members, err
	}
	return members, err
}

func (c *Cx1Client) GetAllGroupMembersFiltered(groupId string, filter GroupMembersFilter) (uint64, []User, error) {
	var all_members []User

	members, err := c.GetGroupMembersFiltered(groupId, filter)
	all_members = members
	count := len(members)

	for err == nil && count > 0 {
		filter.Bump()
		members, err = c.GetGroupMembersFiltered(groupId, filter)
		if len(members) == 0 {
			break
		}
		all_members = append(all_members, members...)
		count = len(all_members)
	}

	return uint64(count), all_members, err
}

// convenience
func (c *Cx1Client) GetOrCreateGroupByName(name string) (Group, error) {
	group, err := c.GetGroupByName(name)
	if err != nil {
		group, err = c.CreateGroup(name)
		if err != nil {
			return group, err
		}
	}

	return group, nil
}

func (g *Group) FindSubgroupByName(name string) (Group, error) {
	for _, s := range g.SubGroups {
		if s.Name == name {
			return s, nil
		} else {
			subg, err := s.FindSubgroupByName(name)
			if err == nil {
				return subg, nil
			}
		}
	}

	return Group{}, fmt.Errorf("group %v does not contain subgroup named %v", g.String(), name)
}

// internal convenience, called from functions that retrieve groups including their subgroups
func setGroupFilled(group *Group) {
	if len(group.SubGroups) == int(group.SubGroupCount) {
		group.Filled = true
	}

	for i := range group.SubGroups {
		setGroupFilled(&group.SubGroups[i])
	}
}
