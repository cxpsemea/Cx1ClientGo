package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

// Returns the total number of matching results plus an array of projects with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c Cx1Client) GetProjectOverviewsFiltered(filter ProjectOverviewFilter) (uint64, []ProjectOverview, error) {
	params, _ := query.Values(filter)

	var ProjectResponse struct {
		BaseFilteredResponse
		Projects []ProjectOverview
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects-overview?%v", params.Encode()), nil, nil)

	if err != nil {
		return ProjectResponse.TotalCount, ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	return ProjectResponse.TotalCount, ProjectResponse.Projects, err
}

// Retrieves all projects matching the filter
func (c Cx1Client) GetAllProjectOverviewsFiltered(filter ProjectOverviewFilter) (uint64, []ProjectOverview, error) {
	var projects []ProjectOverview

	count, err := c.GetProjectOverviewCountFiltered(filter)
	if err != nil {
		return count, projects, err
	}
	_, projects, err = c.GetXProjectOverviewsFiltered(filter, count)
	return count, projects, err
}

// Retrieves the top 'count' projects matching the filter
func (c Cx1Client) GetXProjectOverviewsFiltered(filter ProjectOverviewFilter, count uint64) (uint64, []ProjectOverview, error) {
	var projects []ProjectOverview

	_, projs, err := c.GetProjectOverviewsFiltered(filter)
	projects = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(projects)) < count {
		filter.Bump()
		_, projs, err = c.GetProjectOverviewsFiltered(filter)
		projects = append(projects, projs...)
	}

	if uint64(len(projects)) > count {
		return count, projects[:count], err
	}

	return count, projects, err
}

func (c Cx1Client) GetProjectOverviewCountFiltered(filter ProjectOverviewFilter) (uint64, error) {
	params, _ := query.Values(filter)
	filter.Limit = 1
	c.logger.Debugf("Get Cx1 Project count matching filter: %v", params.Encode())
	count, _, err := c.GetProjectOverviewsFiltered(filter)
	return count, err
}
