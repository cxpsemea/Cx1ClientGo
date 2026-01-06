package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
)

// Get all scan schedules - v3.44+
func (c *Cx1Client) GetAllScanSchedules() ([]ProjectScanSchedule, error) {
	_, schedules, err := c.GetAllScanSchedulesFiltered(ProjectScanScheduleFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.ScanSchedules},
	})
	return schedules, err
}

// Returns the total number of matching results plus an array of schedules with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c *Cx1Client) GetScanSchedulesFiltered(filter ProjectScanScheduleFilter) (uint64, []ProjectScanSchedule, error) {
	params, _ := query.Values(filter)

	var scheduleResponse struct {
		TotalCount         uint64                `json:"total_count"`
		FilteredTotalCount uint64                `json:"filtered_count"`
		Schedules          []ProjectScanSchedule `json:"schedules"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/schedules?%v", params.Encode()), nil, nil)

	if err != nil {
		return scheduleResponse.TotalCount, scheduleResponse.Schedules, err
	}

	err = json.Unmarshal(response, &scheduleResponse)

	for id := range scheduleResponse.Schedules {
		scheduleResponse.Schedules[id].StartTime = scheduleResponse.Schedules[id].NextStartTime.Format("15:04")
	}

	return scheduleResponse.TotalCount, scheduleResponse.Schedules, err
}

// Retrieves all projects matching the filter
func (c *Cx1Client) GetAllScanSchedulesFiltered(filter ProjectScanScheduleFilter) (uint64, []ProjectScanSchedule, error) {
	var projects []ProjectScanSchedule

	count, err := c.GetScanScheduleCountFiltered(filter)
	if err != nil {
		return count, projects, err
	}
	_, projects, err = c.GetXScanSchedulesFiltered(filter, count)
	return count, projects, err
}

// Retrieves the top 'count' projects matching the filter
func (c *Cx1Client) GetXScanSchedulesFiltered(filter ProjectScanScheduleFilter, count uint64) (uint64, []ProjectScanSchedule, error) {
	var projects []ProjectScanSchedule

	_, projs, err := c.GetScanSchedulesFiltered(filter)
	projects = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(projects)) < count {
		filter.Bump()
		_, projs, err = c.GetScanSchedulesFiltered(filter)
		projects = append(projects, projs...)
	}

	if uint64(len(projects)) > count {
		return count, projects[:count], err
	}

	return count, projects, err
}

func (c *Cx1Client) GetScanScheduleCountFiltered(filter ProjectScanScheduleFilter) (uint64, error) {
	filter.Limit = 1
	params, _ := query.Values(filter)
	c.config.Logger.Debugf("Get Cx1 Project count matching filter: %v", params.Encode())
	count, _, err := c.GetScanSchedulesFiltered(filter)
	return count, err
}

// Get scan schedules for a project
func (c *Cx1Client) GetScanSchedulesByID(projectId string) ([]ProjectScanSchedule, error) {
	schedules := []ProjectScanSchedule{}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/schedules/%v", projectId), nil, nil)
	if err != nil {
		return schedules, err
	}

	err = json.Unmarshal(response, &schedules)
	if err != nil {
		return schedules, err
	}

	for id := range schedules {
		schedules[id].StartTime = schedules[id].NextStartTime.Format("15:04")
	}

	return schedules, nil
}

// helper
func prepareScanScheduleBody(s ProjectScanSchedule) ([]byte, error) {
	type ProjectScanScheduleBody struct {
		StartTime string            `json:"start_time"`
		Frequency string            `json:"frequency"`
		Days      []string          `json:"days,omitempty"`
		Active    bool              `json:"active"`
		Engines   []string          `json:"engines"`
		Branch    string            `json:"branch"`
		Tags      map[string]string `json:"tags"`
	}

	schedule := ProjectScanScheduleBody{
		StartTime: s.StartTime,
		Frequency: s.Frequency,
		Days:      s.Days,
		Active:    s.Active,
		Engines:   s.Engines,
		Branch:    s.Branch,
		Tags:      s.Tags,
	}
	return json.Marshal(schedule)
}

func (c *Cx1Client) CreateScanSchedule(project *Project, s ProjectScanSchedule) error {
	if project == nil {
		return fmt.Errorf("project cannot be nil")
	}
	return c.CreateScanScheduleByID(project.ProjectID, s)
}
func (c *Cx1Client) CreateScanScheduleByID(projectId string, s ProjectScanSchedule) error {
	jsonBody, err := prepareScanScheduleBody(s)
	if err != nil {
		return err
	}
	_, err = c.sendRequest(http.MethodPost, fmt.Sprintf("/projects/schedules/%v", projectId), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) UpdateScanSchedule(project *Project, schedule ProjectScanSchedule) error {
	if project == nil {
		return fmt.Errorf("project cannot be nil")
	}
	return c.UpdateScanScheduleByID(project.ProjectID, schedule)
}
func (c *Cx1Client) UpdateScanScheduleByID(projectId string, schedule ProjectScanSchedule) error {
	jsonBody, err := prepareScanScheduleBody(schedule)
	if err != nil {
		return err
	}
	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/projects/schedules/%v", projectId), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) DeleteScanSchedules(project *Project) error {
	return c.DeleteScanSchedulesByID(project.ProjectID)
}
func (c *Cx1Client) DeleteScanSchedulesByID(projectId string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/projects/schedules/%v", projectId), nil, nil)
	return err
}

func (s ProjectScanSchedule) String() string {
	if s.Frequency == "weekly" {
		return fmt.Sprintf("Project %v scan: weekly on %v at %v", s.ProjectID, strings.Join(s.Days, ","), s.StartTime)
	} else {
		return fmt.Sprintf("Project %v scan: daily at %v", s.ProjectID, s.StartTime)
	}
}
