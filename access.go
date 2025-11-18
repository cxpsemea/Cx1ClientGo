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

var IAMResourceTypes = []string{"tenant", "application", "project"}

// Retrieves a specific entity-resource assignment from Access Management
// As of Nov '25 this will not consider implied permissions
// eg: user in group + group has access = user has access but no access assignment
func (c Cx1Client) GetAccessAssignmentByID(entityId, resourceId string) (AccessAssignment, error) {
	c.logger.Debugf("Getting access assignment for entityId %v and resourceId %v", entityId, resourceId)
	var aa AccessAssignment
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/?entity-id=%v&resource-id=%v", entityId, resourceId), nil, nil)

	if err != nil {
		return aa, err
	}

	err = json.Unmarshal(response, &aa)
	return aa, err
}

// Add a specific access assignment
func (c Cx1Client) AddAccessAssignment(access AccessAssignment) error {
	c.logger.Debugf("Creating access assignment for entityId %v and resourceId %v", access.EntityID, access.ResourceID)

	type AccessAssignmentPOST struct {
		TenantID     string   `json:"tenantID"`
		EntityID     string   `json:"entityID"`
		EntityType   string   `json:"entityType"`
		EntityName   string   `json:"entityName"`
		EntityRoles  []string `json:"entityRoles"`
		ResourceID   string   `json:"resourceID"`
		ResourceType string   `json:"resourceType"`
		ResourceName string   `json:"resourceName"`
		CreatedAt    string   `json:"createdAt"`
	}

	flag, _ := c.CheckFlag("ACCESS_MANAGEMENT_PHASE_2")

	roles := make([]string, 0)
	for _, r := range access.EntityRoles {
		if flag {
			roles = append(roles, r.Id)
		} else {
			roles = append(roles, r.Name)
		}
	}

	accessPost := AccessAssignmentPOST{
		TenantID:     access.TenantID,
		EntityID:     access.EntityID,
		EntityType:   access.EntityType,
		EntityName:   access.EntityName,
		EntityRoles:  roles,
		ResourceID:   access.ResourceID,
		ResourceType: access.ResourceType,
		ResourceName: access.ResourceName,
		CreatedAt:    access.CreatedAt,
	}

	body, err := json.Marshal(accessPost)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/access-management", bytes.NewReader(body), nil)
	return err
}

// Get a list of entities that have been granted direct access to a specific resource
// As of Nov '25 this will not consider implied permissions
// eg: user in group + group has access = user has access but no access assignment
func (c Cx1Client) GetEntitiesAccessToResourceByID(resourceId, resourceType string) ([]AccessAssignment, error) {
	c.logger.Debugf("Getting the entities with access assignment for resourceId %v", resourceId)
	var aas []AccessAssignment

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/entities-for?resource-id=%v&resource-type=%v", resourceId, resourceType), nil, nil)
	if err != nil {
		return aas, err
	}

	err = json.Unmarshal(response, &aas)
	return aas, err
}

// Get a list of resources to which this entity has been granted direct access
// As of Nov '25 this will not consider implied permissions
// eg: user in group + group has access = user has access but no access assignment
func (c Cx1Client) GetResourcesAccessibleToEntityByID(entityId, entityType string, resourceTypes []string) ([]AccessAssignment, error) {
	var aas []AccessAssignment
	c.logger.Debugf("Getting the resources accessible to entity %v", entityId)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/resources-for?entity-id=%v&entity-type=%v&resource-types=%v", entityId, entityType, strings.Join(resourceTypes, ",")), nil, nil)
	if err != nil {
		return aas, err
	}

	err = json.Unmarshal(response, &aas)
	if err != nil {
		return aas, err
	}

	return aas, nil
}

// Check if the current user has access to execute a specific action on this resource
func (c Cx1Client) CheckAccessToResourceByID(resourceId, resourceType, action string) (bool, error) {
	c.logger.Debugf("Checking current user access for resource %v and action %v", resourceId, action)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/has-access?resource-id=%v&resource-type=%v&action=%v", resourceId, resourceType, action), nil, nil)
	if err != nil {
		return false, err
	}

	var accessResponse struct {
		AccessGranted bool `json:"accessGranted"`
	}

	err = json.Unmarshal(response, &accessResponse)
	return accessResponse.AccessGranted, err
}

// Check which resources are accessible to this user
func (c Cx1Client) CheckAccessibleResources(resourceTypes []string, action string) (bool, []AccessibleResource, error) {
	c.logger.Debugf("Checking current user accessible resources for action %v", action)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/get-resources?resource-types=%v&action=%v", strings.Join(resourceTypes, ","), action), nil, nil)
	var responseStruct struct {
		All       bool                 `json:"all"`
		Resources []AccessibleResource `json:"resources"`
	}

	if err != nil {
		return responseStruct.All, responseStruct.Resources, err
	}

	err = json.Unmarshal(response, &responseStruct)
	return responseStruct.All, responseStruct.Resources, err
}

func (c Cx1Client) DeleteAccessAssignmentByID(entityId, resourceId string) error {
	c.logger.Debugf("Deleting access assignment between entity %v and resource %v", entityId, resourceId)
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/access-management?resource-id=%v&entity-id=%v", resourceId, entityId), nil, nil)
	return err
}

// IAM phase2?
func (c Cx1Client) GetMyGroups(search string, subgroups bool, limit, offset uint64) ([]Group, error) {
	params := url.Values{}
	params.Add("search", search)
	params.Add("subgroups", strconv.FormatBool(subgroups))
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))
	var groups []Group
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/my-groups?%v", params.Encode()), nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	return groups, err
}

func (c Cx1Client) GetAvailableGroups(search string, projectId string, limit, offset uint64) ([]Group, error) {
	params := url.Values{}
	params.Add("search", search)
	params.Add("project-id", projectId)
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	responseBody := struct {
		Total  uint64  `json:"total"`
		Groups []Group `json:"groups"`
	}{}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/available-groups?%v", params.Encode()), nil, nil)
	if err != nil {
		return responseBody.Groups, err
	}

	err = json.Unmarshal(response, &responseBody)
	return responseBody.Groups, err
}

// These functions will eventually replace the existing Keycloak-backed ones.

// Get groups (from access-management)
func (c Cx1Client) GetAMGroups(search string, groupIds []string, limit, offset uint64) ([]Group, error) {
	params := url.Values{}
	params.Add("search", search)
	params.Add("ids", strings.Join(groupIds, ","))
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	var groups []Group
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/available-groups?%v", params.Encode()), nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	return groups, err
}

// Get users (from access-management)
func (c Cx1Client) GetAMUsers(search string, limit, offset uint64) ([]User, error) {
	params := url.Values{}
	params.Add("search", search)
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/users?%v", params.Encode()), nil, nil)
	if err != nil {
		return nil, err
	}

	var users []User
	err = json.Unmarshal(response, &users)
	return users, err
}

// Get clients (from access-management)
// IAM phase2?
func (c Cx1Client) GetAMClients(search string, limit, offset uint64) ([]OIDCClient, error) {
	params := url.Values{}
	params.Add("search", search)
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/clients?%v", params.Encode()), nil, nil)
	if err != nil {
		return nil, err
	}

	var clients []OIDCClient
	err = json.Unmarshal(response, &clients)
	return clients, err
}

// Get applications (from access-management)
// IAM phase2?
func (c Cx1Client) GetAMApplications(action string, name string, tagsKeys []string, tagsValues []string, limit, offset uint64) ([]Application, error) {
	params := url.Values{}
	params.Add("action", action)
	params.Add("name", name)
	params.Add("tagsKeys", strings.Join(tagsKeys, ","))
	params.Add("tagsValues", strings.Join(tagsValues, ","))
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	responseBody := struct {
		Total         uint64        `json:"totalCount"`
		FilteredTotal uint64        `json:"filteredTotalCount"`
		Applications  []Application `json:"applications"`
	}{}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/applications?%v", params.Encode()), nil, nil)
	if err != nil {
		return responseBody.Applications, err
	}

	err = json.Unmarshal(response, &responseBody)
	return responseBody.Applications, err
}

// Get projects (from access-management)
// IAM phase2?
func (c Cx1Client) GetAMProjects(action string, name string, tagsKeys []string, tagsValues []string, limit, offset uint64) ([]Project, error) {
	params := url.Values{}
	params.Add("action", action)
	params.Add("name", name)
	params.Add("tagsKeys", strings.Join(tagsKeys, ","))
	params.Add("tagsValues", strings.Join(tagsValues, ","))
	params.Add("limit", strconv.FormatUint(limit, 10))
	params.Add("offset", strconv.FormatUint(offset, 10))

	responseBody := struct {
		Total         uint64    `json:"totalCount"`
		FilteredTotal uint64    `json:"filteredTotalCount"`
		Projects      []Project `json:"projects"`
	}{}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/projects?%v", params.Encode()), nil, nil)
	if err != nil {
		return responseBody.Projects, err
	}

	err = json.Unmarshal(response, &responseBody)
	return responseBody.Projects, err
}

// Convenience functions

// Get all resources accessible to a user (IAM Phase1)
// type can be tenant, application, or project
// includeImplied:
//
//	if true, access to an application will return application+projects in app
//	if false, will not list projects in the app (unless those are explicitly assigned)
func (c Cx1Client) GetAllResourcesAccessibleToUserByID(userID string, types []string, includeImplied bool) ([]AccessibleResource, error) {
	resources := []AccessibleResource{}
	if err := c.isIAMVersion(1); err != nil {
		return []AccessibleResource{}, err
	}

	user, err := c.GetUserByID(userID)
	if err != nil {
		return []AccessibleResource{}, err
	}
	_, err = c.GetUserGroups(&user)
	if err != nil {
		return []AccessibleResource{}, err
	}
	allUserRoles, err := c.GetAllUserRoles(&user)
	if err != nil {
		return []AccessibleResource{}, err
	}

	//c.logger.Infof("GetAllResourcesAccessibleToUserByID User %v belongs to groups: %v", user.String(), strings.Join(usergroups, ", "))
	userroles := []string{}
	for _, r := range allUserRoles {
		userroles = append(userroles, r.Name)
	}
	//c.logger.Infof("GetAllResourcesAccessibleToUserByID User %v has roles: %v", user.String(), strings.Join(userroles, ", "))

	resourceTypes := []string{"tenant", "project", "application"}
	user_resources, err := c.GetResourcesAccessibleToEntityByID(userID, "user", resourceTypes)
	if err != nil {
		return []AccessibleResource{}, err
	}
	resources = convertAssignmentsToResources(user_resources)

	for _, g := range user.Groups {
		group_resources, err := c.GetAllResourcesAccessibleToGroupByID(g.GroupID, IAMResourceTypes, false)
		if err != nil {
			return []AccessibleResource{}, err
		}
		resources = mergeAccessibleResources(resources, group_resources, 1)
	}

	// this is IAM phase1 behavior
	grouproles := getDistinctRoles(resources)

	seen := make(map[string]struct{})
	for _, r := range grouproles {
		seen[r] = struct{}{}
	}
	for _, r := range userroles {
		seen[r] = struct{}{}
	}

	all_roles := []string{}
	for r := range seen {
		all_roles = append(all_roles, r)
	}
	slices.Sort(all_roles)
	//c.logger.Infof("GetAllResourcesAccessibleToUserByID All roles combined: %v", strings.Join(all_roles, ", "))

	if includeImplied {
		resources, err = c.fillMissingResources(resources)
		if err != nil {
			return resources, err
		}
	}

	resources = *filterResourcesByType(&resources, types)

	for id := range resources {
		resources[id].Roles = all_roles
	}

	return resources, nil
}

// Get all resources accessible to a group (IAM Phase1)
// type can be tenant, application, or project
// includeImplied:
//
//	if true, access to an application will return application+projects in app
//	if false, will not list projects in the app (unless those are explicitly assigned)
func (c Cx1Client) GetAllResourcesAccessibleToGroupByID(groupID string, types []string, includeImplied bool) ([]AccessibleResource, error) {
	resources := []AccessibleResource{}
	if err := c.isIAMVersion(1); err != nil {
		return resources, err
	}

	group, err := c.GetGroupByID(groupID)
	if err != nil {
		return resources, err
	}

	//c.logger.Infof("Group %v has parent: %v", group.String(), group.ParentID)

	groupRoles, err := c.GetGroupInheritedRoles(&group)
	if err != nil {
		return resources, err
	}
	all_roles := []string{}
	for _, r := range groupRoles {
		all_roles = append(all_roles, r.Name)
	}
	slices.Sort(all_roles)

	resourceTypes := []string{"tenant", "project", "application"}
	group_resources, err := c.GetResourcesAccessibleToEntityByID(groupID, "group", resourceTypes)
	if err != nil {
		return resources, err
	}

	resources = convertAssignmentsToResources(group_resources)

	if group.ParentID != "" {
		parent_resources, err := c.GetAllResourcesAccessibleToGroupByID(group.ParentID, IAMResourceTypes, false)
		if err != nil {
			return resources, err
		}
		resources = mergeAccessibleResources(resources, parent_resources, 1)
	}

	if includeImplied {
		resources, err = c.fillMissingResources(resources)
		if err != nil {
			return resources, err
		}
	}

	resources = *filterResourcesByType(&resources, types)

	for id := range resources {
		resources[id].Roles = all_roles
	}
	// + projects inside accessible apps?

	return resources, nil
}

func (c Cx1Client) CheckIAMVersion() (int, error) {
	flag, err := c.CheckFlag("ACCESS_MANAGEMENT_ENABLED")
	if err != nil {
		return -1, err
	}
	if !flag {
		return -1, nil
	}

	flag, err = c.CheckFlag("ACCESS_MANAGEMENT_PHASE_2")
	if err != nil {
		return 0, err
	}
	if flag {
		return 2, nil
	}
	return 1, nil
}

func (c Cx1Client) isIAMVersion(version int) error {
	iamversion, err := c.CheckIAMVersion()
	if err != nil {
		return err
	}
	if version != iamversion {
		return fmt.Errorf("iam version is %d and not expected %d", iamversion, version)
	}
	return nil
}

func getDistinctRoles(list []AccessibleResource) []string {
	roles := []string{}
	for _, r := range list {
		for _, role := range r.Roles {
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
	}
	slices.Sort(roles)
	return roles
}

func mergeAccessibleResources(list1 []AccessibleResource, list2 []AccessibleResource, _ int) []AccessibleResource {
	merged := []AccessibleResource{}

	for _, r1 := range list1 {
		var matched *AccessibleResource
		for _, r2 := range list2 {
			if r1.ResourceID == r2.ResourceID {
				matched = &r2
				break
			}
		}
		if matched != nil {
			merged = append(merged, mergeAccessibleResourceRoles(r1, *matched))
		} else {
			merged = append(merged, r1)
		}
	}

	for _, r2 := range list2 {
		matched := false
		for _, r1 := range list1 {
			if r1.ResourceID == r2.ResourceID {
				matched = true
				break
			}
		}
		if !matched {
			merged = append(merged, r2)
		}
	}

	return merged
}

func mergeAccessibleResourceRoles(r1, r2 AccessibleResource) AccessibleResource {
	merged := r1

	for _, role := range r2.Roles {
		if !slices.Contains(merged.Roles, role) {
			merged.Roles = append(merged.Roles, role)
		}
	}

	slices.Sort(merged.Roles)

	return merged
}

// if a user has tenant-level access, this will propagate the tenant-level permissions into application-level
// AccessibleResource objects unless an application is explicitly assigned another permission
// if a user has application-level access, this will propagate the application-level permissions into project-level
// AccessibleResource objects unless a project is explicitly assigned another permission
func (c Cx1Client) fillMissingResources(resources []AccessibleResource) ([]AccessibleResource, error) {
	// first check there is any tenant access
	var tenantAccess *AccessibleResource
	for _, r := range resources {
		if r.ResourceType == "tenant" {
			tenantAccess = &r
			break
		}
	}

	seen_applications := make(map[string]*AccessibleResource)
	seen_projects := make(map[string]*AccessibleResource)
	all_applications := []AccessibleResource{}
	all_projects := []AccessibleResource{}

	for _, r := range resources {
		if r.ResourceType == "application" {
			merged_resource := mergeAccessibleResourceRoles(r, *tenantAccess)
			seen_applications[r.ResourceID] = &merged_resource
			all_applications = append(all_applications, merged_resource)
		}
		if r.ResourceType == "project" {
			seen_projects[r.ResourceID] = &r
		}
	}

	applications, err := c.GetAllApplications()
	if err != nil {
		return []AccessibleResource{}, err
	}
	applicationMap := make(map[string]Application)
	for _, a := range applications {
		applicationMap[a.ApplicationID] = a
	}

	projects, err := c.GetAllProjects()
	if err != nil {
		return []AccessibleResource{}, err
	}
	projectMap := make(map[string]Project)
	for _, p := range projects {
		projectMap[p.ProjectID] = p
	}

	if tenantAccess != nil {
		for _, app := range applications {
			var app_resource AccessibleResource
			application := applicationMap[app.ApplicationID]

			if _, ok := seen_applications[app.ApplicationID]; !ok {
				app_resource = AccessibleResource{
					ResourceID:   app.ApplicationID,
					ResourceType: "application",
					ResourceName: application.Name,
					Roles:        tenantAccess.Roles,
				}
				all_applications = append(all_applications, app_resource)
				seen_applications[app.ApplicationID] = &app_resource
			}
		}
	}

	for _, p := range projects {
		projectMap[p.ProjectID] = p
		var effectiveAccess AccessibleResource

		if assignedAccess, ok := seen_projects[p.ProjectID]; !ok { // do not have this project explicitly assigned
			effectiveAccess = AccessibleResource{
				ResourceID:   p.ProjectID,
				ResourceType: "project",
				ResourceName: p.Name,
				Roles:        []string{},
			}
		} else {
			effectiveAccess = *assignedAccess
		}

		if tenantAccess != nil {
			effectiveAccess = mergeAccessibleResourceRoles(effectiveAccess, *tenantAccess)
		}

		for _, a := range *p.Applications {
			if assigned_application, ok := seen_applications[a]; ok {
				effectiveAccess = mergeAccessibleResourceRoles(effectiveAccess, *assigned_application)
			}
		}

		all_projects = append(all_projects, effectiveAccess)
		seen_projects[p.ProjectID] = &effectiveAccess
	}

	var all_resources []AccessibleResource
	if tenantAccess != nil {
		all_resources = append(all_resources, *tenantAccess)
	}
	all_resources = append(all_resources, all_applications...)
	all_resources = append(all_resources, all_projects...)

	return all_resources, nil
}

func filterResourcesByType(resources *[]AccessibleResource, types []string) *[]AccessibleResource {
	same := true
	for _, a := range IAMResourceTypes {
		if !slices.Contains(types, a) {
			same = false
			break
		}
	}
	if same {
		return resources
	}

	filtered := []AccessibleResource{}
	for _, r := range *resources {
		if slices.Contains(types, r.ResourceType) {
			filtered = append(filtered, r)
		}
	}
	return &filtered
}

func convertAssignmentsToResources(assignments []AccessAssignment) []AccessibleResource {
	resources := []AccessibleResource{}
	for _, a := range assignments {
		resources = append(resources, a.ToResource())
	}
	return resources
}

func (a AccessAssignment) ToResource() AccessibleResource {
	ar := AccessibleResource{
		ResourceID:   a.ResourceID,
		ResourceType: a.ResourceType,
		ResourceName: a.ResourceName,
	}

	for _, r := range a.EntityRoles {
		ar.Roles = append(ar.Roles, r.Name)
	}

	return ar
}

func (a AccessibleResource) String() string {
	return fmt.Sprintf("%v [%v] %v: %v", a.ResourceType, ShortenGUID(a.ResourceID), a.ResourceName, strings.Join(a.Roles, ", "))
}
