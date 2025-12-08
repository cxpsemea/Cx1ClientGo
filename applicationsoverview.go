package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

func (c *Cx1Client) GetAllApplicationOverviews() ([]ApplicationOverview, error) {
	c.logger.Debugf("Get All Cx1 Application Overviews")
	_, applications, err := c.GetAllApplicationOverviewsFiltered(ApplicationOverviewFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
	})

	return applications, err
}

// Returns the total number of matching results plus an array of applications with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c *Cx1Client) GetApplicationOverviewsFiltered(filter ApplicationOverviewFilter) (uint64, []ApplicationOverview, error) {
	params, _ := query.Values(filter)

	var ApplicationResponse struct {
		BaseFilteredResponse
		Applications []ApplicationOverview
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications-overview?%v", params.Encode()), nil, nil)

	if err != nil {
		return ApplicationResponse.TotalCount, ApplicationResponse.Applications, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	return ApplicationResponse.TotalCount, ApplicationResponse.Applications, err
}

// Retrieves all applications matching the filter
func (c *Cx1Client) GetAllApplicationOverviewsFiltered(filter ApplicationOverviewFilter) (uint64, []ApplicationOverview, error) {
	var applications []ApplicationOverview

	count, err := c.GetApplicationOverviewCountFiltered(filter)
	if err != nil {
		return count, applications, err
	}
	_, applications, err = c.GetXApplicationOverviewsFiltered(filter, count)
	return count, applications, err
}

// Retrieves the top 'count' applications matching the filter
func (c *Cx1Client) GetXApplicationOverviewsFiltered(filter ApplicationOverviewFilter, count uint64) (uint64, []ApplicationOverview, error) {
	var applications []ApplicationOverview

	_, projs, err := c.GetApplicationOverviewsFiltered(filter)
	applications = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(applications)) < count {
		filter.Bump()
		_, projs, err = c.GetApplicationOverviewsFiltered(filter)
		applications = append(applications, projs...)
	}

	if uint64(len(applications)) > count {
		return count, applications[:count], err
	}

	return count, applications, err
}

func (c *Cx1Client) GetApplicationOverviewCountFiltered(filter ApplicationOverviewFilter) (uint64, error) {
	filter.Limit = 1
	params, _ := query.Values(filter)
	c.logger.Debugf("Get Cx1 Application count matching filter: %v", params.Encode())
	count, _, err := c.GetApplicationOverviewsFiltered(filter)
	return count, err
}

func (o ApplicationOverview) String() string {
	return fmt.Sprintf("application [%v] %v (%d projects) - %v", ShortenGUID(o.ApplicationID), o.Name, o.ProjectNumber, o.RiskLevel)
}
