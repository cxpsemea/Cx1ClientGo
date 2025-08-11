package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

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
