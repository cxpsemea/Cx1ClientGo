package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/go-querystring/query"
	"golang.org/x/exp/slices"
)

// Create a new project
func (c *Cx1Client) CreateProject(projectname string, cx1_group_ids []string, tags map[string]string) (Project, error) {
	c.config.Logger.Debugf("Create Project: %v", projectname)
	data := map[string]interface{}{
		"name":        projectname,
		"groups":      []string{},
		"tags":        map[string]string{},
		"criticality": 3,
	}

	if len(tags) > 0 {
		data["tags"] = tags
	}
	if len(cx1_group_ids) > 0 {
		data["groups"] = cx1_group_ids
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Project{}, err
	}

	var project Project
	response, err := c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.config.Logger.Tracef("Error while creating project %v: %s", projectname, err)
		return project, err
	}

	err = json.Unmarshal(response, &project)
	if project.Applications != nil {
		project.originalApplications = *project.Applications
	} else {
		project.originalApplications = []string{}
	}
	return project, err
}

// Create a new project inside an application
// Does not wait/poll until the project is created and attached to the application
func (c *Cx1Client) CreateProjectInApplicationWOPolling(projectname string, cx1_group_ids []string, tags map[string]string, applicationId string) (Project, error) {
	c.config.Logger.Debugf("Create Project %v in applicationId %v", projectname, applicationId)
	data := map[string]interface{}{
		"name":        projectname,
		"groups":      []string{},
		"tags":        map[string]string{},
		"criticality": 3,
	}

	if len(tags) > 0 {
		data["tags"] = tags
	}
	if len(cx1_group_ids) > 0 {
		data["groups"] = cx1_group_ids
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Project{}, err
	}

	var project Project
	var response []byte
	if check, _ := c.version.CheckCxOne("3.16.0"); check >= 0 {
		data["applicationIds"] = []string{applicationId}
		jsonBody, err = json.Marshal(data)
		if err != nil {
			return Project{}, err
		}
		response, err = c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
	} else {
		response, err = c.sendRequest(http.MethodPost, fmt.Sprintf("/projects/application/%v", applicationId), bytes.NewReader(jsonBody), nil)

		if err != nil && err.Error()[0:8] == "HTTP 404" { // At some point, the api /projects/applications will be removed and instead the normal /projects API will do the job.
			data["applicationIds"] = []string{applicationId}
			jsonBody, err = json.Marshal(data)
			if err != nil {
				return Project{}, err
			}
			response, err = c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
		}
	}

	if err != nil {
		c.config.Logger.Tracef("Error while creating project %v: %s", projectname, err)
		return project, err
	}

	err = json.Unmarshal(response, &project)
	if err != nil {
		return Project{}, err
	}

	if project.Applications != nil {
		project.originalApplications = *project.Applications
	} else {
		project.originalApplications = []string{}
	}
	return project, err
}

// Create a project in an application and poll until the project is created and attached to the application
func (c *Cx1Client) CreateProjectInApplication(projectname string, cx1_group_ids []string, tags map[string]string, applicationId string) (Project, error) {
	project, err := c.CreateProjectInApplicationWOPolling(projectname, cx1_group_ids, tags, applicationId)
	if err != nil {
		return project, err
	}
	time.Sleep(time.Second)
	return c.ProjectInApplicationPollingByID(project.ProjectID, applicationId)
}

// Poll a specific project until it shows as attached to the application, by ID
func (c *Cx1Client) ProjectInApplicationPollingByID(projectId, applicationId string) (Project, error) {
	return c.ProjectInApplicationPollingByIDWithTimeout(projectId, applicationId, c.config.Polling.ProjectApplicationLinkPollingDelaySeconds, c.config.Polling.ProjectApplicationLinkPollingMaxSeconds)
}

// Poll a specific project until it shows as attached to the application, by ID
// Polling occurs every delaySeconds until maxSeconds is reached
func (c *Cx1Client) ProjectInApplicationPollingByIDWithTimeout(projectId, applicationId string, delaySeconds, maxSeconds int) (Project, error) {
	project, err := c.GetProjectByID(projectId)
	pollingCounter := 0
	for err != nil || !slices.Contains(*project.Applications, applicationId) {
		if pollingCounter > maxSeconds {
			return project, fmt.Errorf("project %v is not assigned to application ID %v after %d seconds, aborting", projectId, applicationId, maxSeconds)
		}
		c.config.Logger.Debugf("Project is not yet assigned to the application, polling")
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		project, err = c.GetProjectByID(projectId)
		pollingCounter += delaySeconds
	}
	return project, nil
}

// Get up to count # of projects
// behind the scenes this will use the configured pagination (Get/SetPaginationSettings)
func (c *Cx1Client) GetProjects(count uint64) ([]Project, error) {
	c.config.Logger.Debugf("Get %d Cx1 Projects", count)
	_, projects, err := c.GetXProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Projects},
	}, count)

	return projects, err
}

// Get all of the projects
// behind the scenes this will use the configured pagination (Get/SetPaginationSettings)
// behaves the same as GetProjects(# of projects in the environment)
func (c *Cx1Client) GetAllProjects() ([]Project, error) {
	c.config.Logger.Debugf("Get All Cx1 Projects")
	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Projects},
	})
	return projects, err
}

// Get a specific project by ID
func (c *Cx1Client) GetProjectByID(projectID string) (Project, error) {
	c.config.Logger.Debugf("Getting Project with ID %v...", projectID)
	var project Project

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/%v", projectID), nil, nil)
	if err != nil {
		return project, fmt.Errorf("failed to fetch project %v: %s", projectID, err)
	}

	err = json.Unmarshal(data, &project)
	if err != nil {
		return project, err
	}
	if project.Applications != nil {
		project.originalApplications = *project.Applications
	} else {
		project.originalApplications = []string{}
	}

	err = c.GetProjectConfiguration(&project)
	return project, err
}

// case-sensitive exact match for a project name
func (c *Cx1Client) GetProjectByName(name string) (Project, error) {
	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Projects},
		Names:      []string{name},
	})

	if err != nil {
		return Project{}, err
	}

	for _, p := range projects {
		if p.Name == name {
			err = c.GetProjectConfiguration(&p)
			return p, err
		}
	}

	return Project{}, fmt.Errorf("no project matching %v found", name)
}

// Get all projects with names matching the search 'name'
// As of 2024-10-17 this function no longer takes a specific limit as a parameter
// To set limits, offsets, and other parameters directly, use GetProjectsFiltered
func (c *Cx1Client) GetProjectsByName(name string) ([]Project, error) {
	c.config.Logger.Debugf("Get Cx1 Projects By Name: %v", name)

	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Projects},
		Name:       name,
	})

	return projects, err
}

// Get all projects in the group 'groupID' with names matching the search 'name'
func (c *Cx1Client) GetProjectsByNameAndGroupID(projectName string, groupID string) ([]Project, error) {
	c.config.Logger.Debugf("Getting projects with name %v of group ID %v...", projectName, groupID)

	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Projects},
		Name:       projectName,
		Groups:     []string{groupID},
	})

	return projects, err
}

// Underlying function used by many GetProject* calls
// Returns the total number of matching results plus an array of projects with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c *Cx1Client) GetProjectsFiltered(filter ProjectFilter) (uint64, []Project, error) {
	params, _ := query.Values(filter)

	var ProjectResponse struct {
		BaseFilteredResponse
		Projects []Project
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects?%v", params.Encode()), nil, nil)

	if err != nil {
		return ProjectResponse.FilteredTotalCount, ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	return ProjectResponse.FilteredTotalCount, ProjectResponse.Projects, err
}

// Retrieves all projects matching the filter
func (c *Cx1Client) GetAllProjectsFiltered(filter ProjectFilter) (uint64, []Project, error) {
	var projects []Project

	count, err := c.GetProjectCountFiltered(filter)
	if err != nil {
		return count, projects, err
	}
	_, projects, err = c.GetXProjectsFiltered(filter, count)
	return count, projects, err
}

// Retrieves the top 'count' projects matching the filter
func (c *Cx1Client) GetXProjectsFiltered(filter ProjectFilter, count uint64) (uint64, []Project, error) {
	var projects []Project

	_, projs, err := c.GetProjectsFiltered(filter)
	projects = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(projects)) < count {
		filter.Bump()
		_, projs, err = c.GetProjectsFiltered(filter)
		projects = append(projects, projs...)
	}

	for i := range projects {
		if projects[i].Applications != nil {
			projects[i].originalApplications = *projects[i].Applications
		} else {
			projects[i].originalApplications = []string{}
		}
	}

	if uint64(len(projects)) > count {
		return count, projects[:count], err
	}

	return count, projects, err
}

// check if project is assigned to a group by ID
func (p *Project) IsInGroupID(groupId string) bool {
	for _, g := range p.Groups {
		if g == groupId {
			return true
		}
	}
	return false
}

// check if project is assigned to a group
func (p *Project) IsInGroup(group *Group) bool {
	return p.IsInGroupID(group.GroupID)
}

// check if project is assigned to an application by ID
func (p *Project) IsInApplicationID(appId string) bool {
	for _, g := range *p.Applications {
		if g == appId {
			return true
		}
	}
	return false
}

// check if project is assigned to an application
func (p *Project) IsInApplication(app *Application) bool {
	return p.IsInApplicationID(app.ApplicationID)
}

// Get the project's configuration and update the project.Configuration field
func (c *Cx1Client) GetProjectConfiguration(project *Project) error {
	configurations, err := c.GetProjectConfigurationByID(project.ProjectID)
	project.Configuration = configurations
	return err
}

// return the configuration settings for scans set on the tenant level
// this will list default configurations like presets, incremental scan settings etc if set
func (c *Cx1Client) GetTenantConfiguration() ([]ConfigurationSetting, error) {
	c.config.Logger.Debugf("Getting tenant configuration")
	var tenantConfigurations []ConfigurationSetting
	data, err := c.sendRequest(http.MethodGet, "/configuration/tenant", nil, nil)

	if err != nil {
		c.config.Logger.Tracef("Failed to get tenant configuration: %v", err)
		return tenantConfigurations, err
	}

	err = json.Unmarshal([]byte(data), &tenantConfigurations)
	return tenantConfigurations, err
}

// return the configuration settings for scans set on the project level
// this will list default configurations like presets, incremental scan settings etc if set
func (c *Cx1Client) GetProjectConfigurationByID(projectID string) ([]ConfigurationSetting, error) {
	c.config.Logger.Debugf("Getting project configuration for project %v", projectID)
	var projectConfigurations []ConfigurationSetting
	params := url.Values{
		"project-id": {projectID},
	}
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/configuration/project?%v", params.Encode()), nil, nil)

	if err != nil {
		c.config.Logger.Tracef("Failed to get project configuration for project ID %v: %s", projectID, err)
		return projectConfigurations, err
	}

	err = json.Unmarshal([]byte(data), &projectConfigurations)
	return projectConfigurations, err
}

// updates the configuration of the project eg: preset, incremental scans
func (c *Cx1Client) UpdateProjectConfiguration(project *Project, settings []ConfigurationSetting) error {
	project.Configuration = settings
	return c.UpdateProjectConfigurationByID(project.ProjectID, settings)
}

// update the project's configuration
func (c *Cx1Client) UpdateProjectConfigurationByID(projectID string, settings []ConfigurationSetting) error {
	if len(settings) == 0 {
		return fmt.Errorf("empty list of settings provided")
	}

	params := url.Values{
		"project-id": {projectID},
	}

	jsonBody, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/configuration/project?%v", params.Encode()), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.config.Logger.Tracef("Failed to update project %v configuration: %s", projectID, err)
		return err
	}

	return nil
}

// Set a project's configured git branch
func (c *Cx1Client) SetProjectBranchByID(projectID, branch string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.handler.git.branch"
	setting.Value = branch
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

// retrieves all branches for a project
func (c *Cx1Client) GetProjectBranchesByID(projectID string) ([]string, error) {
	return c.GetAllProjectBranchesFiltered(ProjectBranchFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.Branches},
		ProjectID:  projectID,
	})
}

// retrieves a page (filter.Offset to filter.Offset+filter.Limit) of branches for a project
func (c *Cx1Client) GetProjectBranchesFiltered(filter ProjectBranchFilter) ([]string, error) {
	params, _ := query.Values(filter)
	branches := []string{}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/branches?%v", params.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch branches matching filter %v: %s", params, err)
		c.config.Logger.Tracef("Error: %s", err)
		return branches, err
	}

	err = json.Unmarshal(data, &branches)
	return branches, err
}

// returns all of a project's branches matching a filter
func (c *Cx1Client) GetAllProjectBranchesFiltered(filter ProjectBranchFilter) ([]string, error) {
	var branches []string

	bs, err := c.GetProjectBranchesFiltered(filter)
	branches = bs

	for err == nil && filter.Limit == uint64(len(bs)) && filter.Limit > 0 {
		filter.Bump()
		bs, err = c.GetProjectBranchesFiltered(filter)
		branches = append(branches, bs...)
	}

	return branches, err
}

// retrieves the first X of a project's branches matching a filter
func (c *Cx1Client) GetXProjectBranchesFiltered(filter ProjectBranchFilter, count uint64) ([]string, error) {
	var branches []string

	bs, err := c.GetProjectBranchesFiltered(filter)
	branches = bs

	for err == nil && filter.Limit == uint64(len(bs)) && filter.Limit > 0 && uint64(len(branches)) < count {
		filter.Bump()
		bs, err = c.GetProjectBranchesFiltered(filter)
		branches = append(branches, bs...)
	}

	if uint64(len(branches)) > count {
		return branches[:count], err
	}

	return branches, err
}

// Get the count of all projects in the system
func (c *Cx1Client) GetProjectCount() (uint64, error) {
	c.config.Logger.Debugf("Get Cx1 Projects Count")
	count, _, err := c.GetProjectsFiltered(ProjectFilter{BaseFilter: BaseFilter{Limit: 1}})
	return count, err
}

// returns the number of projects with names matching a search string 'name'
func (c *Cx1Client) GetProjectCountByName(name string) (uint64, error) {
	c.config.Logger.Debugf("Get Cx1 Project count by name: %v", name)
	count, _, err := c.GetProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: 1},
		Name:       name,
	})
	return count, err
}

// Get the count of all projects matching the filter
func (c *Cx1Client) GetProjectCountFiltered(filter ProjectFilter) (uint64, error) {
	filter.Limit = 1
	params, _ := query.Values(filter)
	c.config.Logger.Debugf("Get Cx1 Project count matching filter: %v", params.Encode())
	count, _, err := c.GetProjectsFiltered(filter)
	return count, err
}

// Returns a URL to the project's overview page
func (c *Cx1Client) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/projects/%v/overview", c.config.BaseUrl, p.ProjectID)
}

// Sets a project's default repository configuration
func (c *Cx1Client) SetProjectRepositoryByID(projectID, repository string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.handler.git.repository"
	setting.Value = repository
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

// Sets a project's default preset configuration
func (c *Cx1Client) SetProjectPresetByID(projectID, presetName string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.presetName"
	setting.Value = presetName
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

// Sets a project's default language mode (single/multi language scanning)
func (c *Cx1Client) SetProjectLanguageModeByID(projectID, languageMode string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.languageMode"
	setting.Value = languageMode
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

// Sets a projet's default file filter
func (c *Cx1Client) SetProjectFileFilterByID(projectID, filter string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.filter"
	setting.Value = filter
	setting.AllowOverride = allowOverride

	// TODO - apply the filter across all languages? set up separate calls per engine? engine as param?

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

// Directly assign a project to one or more applications
// This should be used separately from the Project.AssignApplication + UpdateProject(Project) flow
func (c *Cx1Client) AssignProjectToApplicationsByIDs(projectId string, applicationIds []string) error {
	if flag, _ := c.CheckFlag("DIRECT_APP_ASSOCIATION_ENABLED"); !flag {
		return fmt.Errorf("direct app association is not enabled")
	}
	var body struct {
		Applications []string `json:"applicationIds"`
	}
	body.Applications = applicationIds
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPost, fmt.Sprintf("/projects/%v/applications", projectId), bytes.NewReader(jsonBody), nil)
	return err
}

// Directly assign a project to one or more applications
// This should be used separately from the Project.AssignApplication + UpdateProject(Project) flow
func (c *Cx1Client) RemoveProjectFromApplicationsByIDs(projectId string, applicationIds []string) error {
	if flag, _ := c.CheckFlag("DIRECT_APP_ASSOCIATION_ENABLED"); !flag {
		return fmt.Errorf("direct app association is not enabled")
	}
	var body struct {
		Applications []string `json:"applicationIds"`
	}
	body.Applications = applicationIds
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodDelete, fmt.Sprintf("/projects/%v/applications", projectId), bytes.NewReader(jsonBody), nil)
	return err
}

// This function patches a project, changing only the fields supplied to the function.
// The project behind the supplied pointer is not changed
// For CheckmarxOne v3.41+
func (c *Cx1Client) PatchProject(project *Project, update ProjectPatch) error {
	return c.PatchProjectByID(project.ProjectID, update)
}

// This function patches a project, changing only the fields supplied to the function.
// For CheckmarxOne v3.41+
func (c *Cx1Client) PatchProjectByID(projectId string, update ProjectPatch) error {
	jsonBody, err := json.Marshal(update)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/projects/%v", projectId), bytes.NewReader(jsonBody), nil)
	return err
}

// This updates a project, including any changes in Application membership. All fields are updated based on the provided data.
// The project behind the supplied pointer is not changed
// For partial updates use PatchProject
func (c *Cx1Client) UpdateProject(project *Project) error {
	c.config.Logger.Debugf("Updating project %v", project.String())

	// This may be temporary depending on how the API changes
	// sending an applicationIds array will cause the project's membership in applications to change
	// this can result in unintentional changes, eg:
	//   project is in app1&app2, user has access only to app1
	//   retrieving the project will list only app1 in the applicationIds array
	//   saving the project may unassign the project from app2
	project_copy := *project

	added := []string{}
	removed := []string{}
	if project_copy.Applications != nil {
		for _, app := range *project_copy.Applications {
			if !slices.Contains(project_copy.originalApplications, app) {
				added = append(added, app)
			}
		}
		for _, app := range project_copy.originalApplications {
			if !slices.Contains(*project_copy.Applications, app) {
				removed = append(removed, app)
			}
		}
		if len(added) == 0 && len(removed) == 0 { // no changes were made to the applications list, so omit this field when doing the PUT
			project_copy.Applications = nil
		}
	}

	jsonBody, err := json.Marshal(project_copy)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/projects/%v", project.ProjectID), bytes.NewReader(jsonBody), nil)
	return err
}

// Delete the project
// There is no UNDO
func (c *Cx1Client) DeleteProject(p *Project) error {
	c.config.Logger.Debugf("Deleting Project %v", p.String())

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/projects/%v", p.ProjectID), nil, nil)
	if err != nil {
		return fmt.Errorf("deleting project %v failed: %s", p.String(), err)
	}

	return nil
}

// Assign a project to a group. You must call UpdateProject() on this project to save the changes.
func (p *Project) AssignGroup(group *Group) {
	if p.IsInGroup(group) {
		return
	}
	p.Groups = append(p.Groups, group.GroupID)
}

// Assign a project to an application. You must call UpdateProject() on this project to save the changes.
func (p *Project) AssignApplication(app *Application) {
	if p.IsInApplication(app) {
		return
	}
	newApps := append(*p.Applications, app.ApplicationID)
	p.Applications = &newApps
	if !slices.Contains(*app.ProjectIds, p.ProjectID) {
		newProjs := append(*app.ProjectIds, p.ProjectID)
		app.ProjectIds = &newProjs
	}
}

// this should only be used if you are separately tracking changes to the Application or have direct_app_association enabled
func (p *Project) AssignApplicationByID(appId string) {
	if p.IsInApplicationID(appId) {
		return
	}
	newApps := append(*p.Applications, appId)
	p.Applications = &newApps
}

// Remove a project from an application and vice versa.
// Requires the project or application to be saved via UpdateProject/UpdateApplication to take effect
func (p *Project) RemoveApplication(app *Application) {
	if !p.IsInApplication(app) {
		return
	}
	newApps := slices.Delete(*p.Applications, slices.Index(*p.Applications, app.ApplicationID), slices.Index(*p.Applications, app.ApplicationID)+1)
	p.Applications = &newApps
	if slices.Contains(*app.ProjectIds, p.ProjectID) {
		newProjs := slices.Delete(*app.ProjectIds, slices.Index(*app.ProjectIds, p.ProjectID), slices.Index(*app.ProjectIds, p.ProjectID)+1)
		app.ProjectIds = &newProjs
	}
}

// this should only be used if you are separately tracking changes to the Application or have direct_app_association enabled
func (p *Project) RemoveApplicationByID(appID string) {
	if !p.IsInApplicationID(appID) {
		return
	}
	newApps := slices.Delete(*p.Applications, slices.Index(*p.Applications, appID), slices.Index(*p.Applications, appID)+1)
	p.Applications = &newApps
}

func (c *Cx1Client) GetOrCreateProjectByName(name string) (Project, error) {
	project, err := c.GetProjectByName(name)
	if err == nil {
		return project, nil
	}

	return c.CreateProject(name, []string{}, map[string]string{})
}

// Find a specific project by name. Should be in a specific application by name.
// If the project doesn't exist, it is created
func (c *Cx1Client) GetOrCreateProjectInApplicationByName(projectName, applicationName string) (Project, Application, error) {
	var application Application
	var project Project
	var err error
	application, err = c.GetApplicationByName(applicationName)
	if err != nil {
		application, err = c.CreateApplication(applicationName)
		if err != nil {
			return project, application, fmt.Errorf("attempt to create project %v in application %v failed, application did not exist and could not be created due to error: %s", projectName, applicationName, err)
		}
	}

	project, err = c.GetProjectByName(projectName)
	if err != nil {
		if err.Error()[:19] == "no project matching" {
			project, err = c.CreateProjectInApplication(projectName, []string{}, map[string]string{}, application.ApplicationID)
			if err != nil {
				return project, application, fmt.Errorf("attempt to create project %v in application %v failed due to error: %s", projectName, applicationName, err)
			}
			return project, application, nil
		} else {
			return project, application, err
		}
	}

	return project, application, nil
}

// Moves a project from one application to another in one operation
// This is necessary for limited-permission users with application-based access assignments
func (c *Cx1Client) MoveProjectBetweenApplications(project *Project, sourceApplicationIDs, destinationApplicationIDs []string) error {
	var requestBody struct {
		Source []string `json:"applicationIdsToDisassociate"`
		Dest   []string `json:"applicationIdsToAssociate"`
	}
	requestBody.Source = sourceApplicationIDs
	requestBody.Dest = destinationApplicationIDs

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/projects/reassign/%v", project.ProjectID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}
	return nil
}

// Returns a specific configuration by 'key'
func (p Project) GetConfigurationByName(configKey string) *ConfigurationSetting {
	return getConfigurationByKey(&p.Configuration, configKey)
}

func (p Project) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(p.ProjectID), p.Name)
}

func (p *Project) GetTags() string {
	str := ""
	for key, val := range p.Tags {
		if str == "" {
			str = key + " = " + val
		} else {
			str = str + ", " + key + " = " + val
		}
	}
	return str
}
