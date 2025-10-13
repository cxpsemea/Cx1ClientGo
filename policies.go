package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

func (f *BasePolicyFilter) Bump() {
	f.Page++
}

func (c Cx1Client) GetAllPolicies() ([]Policy, error) {
	_, policies, err := c.GetAllPoliciesFiltered(PolicyFilter{BasePolicyFilter{Limit: c.pagination.Policies, Page: 1}})
	return policies, err
}

// Underlying function used by many GetPolicy* calls
// Returns the total number of matching results plus an array of policies with
// one page of results (from filter.Page*filter.Limit to (filter.Page+1)*filter.Limit)
func (c Cx1Client) GetPoliciesFiltered(filter PolicyFilter) (uint64, []Policy, error) {
	params, _ := query.Values(filter)

	var PolicyResponse struct {
		Policies           []Policy
		FilteredTotalCount uint64 `json:"filteredPoliciesCount"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/policy_management_service_uri/policies/v2?%v", params.Encode()), nil, nil)

	if err != nil {
		return PolicyResponse.FilteredTotalCount, PolicyResponse.Policies, err
	}

	err = json.Unmarshal(response, &PolicyResponse)
	return PolicyResponse.FilteredTotalCount, PolicyResponse.Policies, err
}

// Retrieves all policies matching the filter
func (c Cx1Client) GetAllPoliciesFiltered(filter PolicyFilter) (uint64, []Policy, error) {
	var policies []Policy

	count, err := c.GetPolicyCountFiltered(filter)
	if err != nil {
		return count, policies, err
	}
	_, policies, err = c.GetXPoliciesFiltered(filter, count)
	return count, policies, err
}

// Retrieves the top 'count' policies matching the filter
func (c Cx1Client) GetXPoliciesFiltered(filter PolicyFilter, count uint64) (uint64, []Policy, error) {
	var policies []Policy

	_, projs, err := c.GetPoliciesFiltered(filter)
	policies = projs

	for err == nil && count > filter.Page*filter.Limit && filter.Limit > 0 && uint64(len(policies)) < count {
		filter.Bump()
		_, projs, err = c.GetPoliciesFiltered(filter)
		policies = append(policies, projs...)
	}

	if uint64(len(policies)) > count {
		return count, policies[:count], err
	}

	return count, policies, err
}

func (c Cx1Client) GetPolicyCountFiltered(filter PolicyFilter) (uint64, error) {
	params, _ := query.Values(filter)
	filter.Limit = 1
	c.logger.Debugf("Get Cx1 Policy count matching filter: %v", params.Encode())
	count, _, err := c.GetPoliciesFiltered(filter)
	return count, err
}

func (c Cx1Client) GetAllPolicyViolations() ([]PolicyViolation, error) {
	_, PolicyViolations, err := c.GetAllPolicyViolationsFiltered(PolicyViolationFilter{BasePolicyFilter{Limit: c.pagination.PolicyViolations, Page: 1}})
	return PolicyViolations, err
}

// Underlying function used by many GetPolicyViolation* calls
// Returns the total number of matching results plus an array of PolicyViolations with
// one page of results (from filter.Page*filter.Limit to (filter.Page+1)*filter.Limit)
func (c Cx1Client) GetPolicyViolationsFiltered(filter PolicyViolationFilter) (uint64, []PolicyViolation, error) {
	params, _ := query.Values(filter)

	var PolicyViolationResponse struct {
		PolicyViolations   []PolicyViolation `json:"incidents"`
		FilteredTotalCount uint64            `json:"filteredIncidentsCount"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/policy_management_service_uri/incidents/filters?%v", params.Encode()), nil, nil)
	if err != nil {
		return PolicyViolationResponse.FilteredTotalCount, PolicyViolationResponse.PolicyViolations, err
	}

	err = json.Unmarshal(response, &PolicyViolationResponse)
	return PolicyViolationResponse.FilteredTotalCount, PolicyViolationResponse.PolicyViolations, err
}

// Retrieves all PolicyViolations matching the filter
func (c Cx1Client) GetAllPolicyViolationsFiltered(filter PolicyViolationFilter) (uint64, []PolicyViolation, error) {
	var PolicyViolations []PolicyViolation

	count, err := c.GetPolicyViolationCountFiltered(filter)
	if err != nil {
		return count, PolicyViolations, err
	}
	_, PolicyViolations, err = c.GetXPolicyViolationsFiltered(filter, count)
	return count, PolicyViolations, err
}

// Retrieves the top 'count' PolicyViolations matching the filter
func (c Cx1Client) GetXPolicyViolationsFiltered(filter PolicyViolationFilter, count uint64) (uint64, []PolicyViolation, error) {
	var PolicyViolations []PolicyViolation

	_, projs, err := c.GetPolicyViolationsFiltered(filter)
	PolicyViolations = projs

	for err == nil && count > (filter.Page+1)*filter.Limit && filter.Limit > 0 && uint64(len(PolicyViolations)) < count {
		filter.Bump()
		_, projs, err = c.GetPolicyViolationsFiltered(filter)
		PolicyViolations = append(PolicyViolations, projs...)
	}

	if uint64(len(PolicyViolations)) > count {
		return count, PolicyViolations[:count], err
	}

	return count, PolicyViolations, err
}

func (c Cx1Client) GetPolicyViolationCountFiltered(filter PolicyViolationFilter) (uint64, error) {
	params, _ := query.Values(filter)
	filter.Limit = 1
	c.logger.Debugf("Get Cx1 PolicyViolation count matching filter: %v", params.Encode())
	count, _, err := c.GetPolicyViolationsFiltered(filter)
	return count, err
}

func (p Policy) String() string {
	status := ""
	if p.IsActivated {
		status += " Active"
	}
	if p.DefaultPolicy {
		status += " Default"
	}
	return fmt.Sprintf("[%v] %v%v", p.PolicyID, p.Name, status)
}

func (pv PolicyViolation) String() string {
	return fmt.Sprintf("[%v] [%d] %v - Project %v (scan [%v])", pv.ScanDate, pv.ViolationID, pv.PolicyName, pv.ProjectName, ShortenGUID(pv.ScanID))
}

func (c Cx1Client) GetPolicyViolationDetailsByID(projectId string, scanId string) (PolicyViolationDetails, error) {
	var details PolicyViolationDetails

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/policy_management_service_uri/evaluation?astProjectId=%v&scanId=%v", projectId, scanId), nil, nil)
	if err != nil {
		return details, err
	}

	err = json.Unmarshal(response, &details)
	return details, err

}
