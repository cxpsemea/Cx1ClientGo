package Cx1ClientGo

import (
    "fmt"
    "net/http"
	"time"
	"net/url"
	"io/ioutil"
	"strings"
	"encoding/json"
	"bytes"
    "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strconv"
)

func init() {
	
}

type Cx1client struct {
	httpClient *http.Client
	authToken string
	baseUrl string
	iamUrl string
	tenant string
}

type Group struct {
	GroupID string
	Name string
//	Path string // ignoring for now
//  SubGroups string // ignoring for now
}






type Preset struct {
	PresetID int        `yaml:"id"`
	Name string         `yaml:"name"`
}



type Project struct {
    ProjectID           string              `json:"id"`
    Name                string              `json:"name"`
    CreatedAt           string              `json:"createdAt"`
    UpdatedAt           string              `json:"updatedAt"`
    Groups              []string            `json:"groups"`
    Tags                map[string]string   `json:"tags"`
    RepoUrl             string              `json:"repoUrl"`
    MainBranch          string              `json:"mainBranch"`
    Origin              string              `json:"origin"`
    Criticality         int                 `json:"criticality"`
}

type ProjectConfigurationSetting struct {
    Key                 string              `json:"key"`
    Name                string              `json:"name"`
    Category            string              `json:"category"`
    OriginLevel         string              `json:"originLevel"`
    Value               string              `json:"value"`
    ValueType           string              `json:"valuetype"`
    ValueTypeParams     string              `json:"valuetypeparams"`
    AllowOverride       bool                `json:"allowOverride"`
}

type Query struct {
	QueryID string
	Name string
}

type ReportStatus struct {
    ReportID            string              `json:"reportId"`
    Status              string              `json:"status"`
    ReportURL           string              `json:"url"`
}

type RunningScan struct {
	ScanID string
	Status string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Scan struct {
    ScanID   string  `json:"id"`
    Status string `json:"status"`
    StatusDetails []ScanStatusDetails  `json:"statusDetails"`
    Branch string `json:"branch"`
    CreatedAt string `json:"createdAt"`
    UpdatedAt string `json:"updatedAt"`
    ProjectID string `json:"projectId"`
    ProjectName string `json:"projectName"`
    UserAgent string `json:"userAgent"`
    Initiator string `json:"initiator"`
    Tags map[string]string `json:"tags"`
    Metadata struct {
        Type string `json:"type"`
        Configs []ScanConfiguration `json:"configs"`
    } `json:"metadata"`
    Engines []string `json:"engines"`
    SourceType string `json:"sourceType"`
    SourceOrigin string `json:"sourceOrigin"`
}

type ScanConfiguration struct {
    ScanType string `json:"type"`
    Values map[string]string `json:"value"`
}

type ScanStatusDetails struct {
    Name            string `json:"name"`
    Status          string `json:"status"`
    Details         string `json:"details"`
}

type Status struct {
    ID      int                 `json:"id"`
    Name    string              `json:"name"`
    Details ScanStatusDetails   `json:"details"`
}

type User struct {
	UserID string
	FirstName string
	LastName string
	UserName string
}

type WorkflowLog struct {
    Source              string              `json:"Source"`
    Info                string              `json:"Info"`
    Timestamp           string              `json:"Timestamp"`
}


// internal calls

func (c Cx1client) get( api string ) (string,error) {

	cx1_req, err := http.NewRequest(http.MethodGet, c.baseUrl + api, nil)
	cx1_req.Header.Add( "Authorization", "Bearer " + c.authToken )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	
	res, err := c.httpClient.Do( cx1_req );
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}	
	defer res.Body.Close()

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	return string(resBody), nil
}
func (c Cx1client) post( api string, data map[string]interface{} ) (string,error) {
	jsonBody, err := json.Marshal(data)
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}
	cx1_req, err := http.NewRequest(http.MethodPost, c.baseUrl + api, strings.NewReader( string(jsonBody) ) )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	cx1_req.Header.Add( "Authorization", "Bearer " + c.authToken )
	cx1_req.Header.Add( "Content-Type", "application/json" )

	log.Trace( "Posting to " + api + ": " + string(jsonBody) )

	

	
	res, err := c.httpClient.Do( cx1_req );
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}	
	defer res.Body.Close()

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	return string(resBody), nil
}

func (c Cx1client) getIAM( api_base string, api string ) (string, error) {
	rurl := c.iamUrl + api_base + c.tenant + api
	log.Trace( "Get from IAM " + rurl )
	cx1_req, err := http.NewRequest(http.MethodGet,rurl, nil)
	cx1_req.Header.Add( "Authorization", "Bearer " + c.authToken )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	
	res, err := c.httpClient.Do( cx1_req );
	defer res.Body.Close()

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	return string(resBody), nil
}
func (c Cx1client) postIAM( api_base string, api string, data map[string]interface{} ) (string,error) {
	rurl := c.iamUrl + api_base + c.tenant + api

	jsonBody, err := json.Marshal(data)
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}
	log.Trace( "Posting to IAM " + rurl + ": " + string(jsonBody) )

	cx1_req, err := http.NewRequest(http.MethodPost, rurl, strings.NewReader(string(jsonBody)) )
	cx1_req.Header.Add( "Content-Type", "application/json" )
	cx1_req.Header.Add( "Authorization", "Bearer " + c.authToken )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	res, err := c.httpClient.Do( cx1_req );
	defer res.Body.Close()

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	return string(resBody), nil
}

// special call for zip-upload 
func (c Cx1client) PutFile( URL string, filename string ) (string,error) {
	log.Trace( "Putting file " + filename + " to " + URL )

	fileContents, err := ioutil.ReadFile(filename)
    if err != nil {
    	log.Error("Failed to Read the File "+ filename + ": " + err.Error())
		return "", err
    }

	cx1_req, err := http.NewRequest(http.MethodPut, URL, bytes.NewReader( fileContents ) )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	cx1_req.Header.Add( "Content-Type", "application/zip" )
	cx1_req.Header.Add( "Authorization", "Bearer " + c.authToken )
	cx1_req.ContentLength = int64(len(fileContents))

	log.Trace( "File contents: " + string(fileContents) )

	res, err := c.httpClient.Do( cx1_req );
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}
	defer res.Body.Close()

	
	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	return string(resBody), nil
}

// Authentication and init

func New( token string, base_url string, iam_url string, tenant string ) *Cx1client {
	cli := Cx1client{ &http.Client{}, token, base_url, iam_url, tenant }
	return &cli
}

func GetTokenOIDC( iam_url string, tenant string, client_id string, client_secret string ) (string, error) {
	login_url := iam_url + "/auth/realms/" + tenant + "/protocol/openid-connect/token"
	
	data := url.Values{}
	data.Set( "grant_type", "client_credentials" )
	data.Set( "client_id", client_id )
	data.Set( "client_secret", client_secret )

	
	log.Info( "Authenticating with Cx1 at: "+login_url )

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add( "Content-Type", "application/x-www-form-urlencoded" )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}
	
	cli := &http.Client{}
	res, err := cli.Do( cx1_req );
	defer res.Body.Close()

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}


	//log.Trace( "  received response: " + string(resBody) )
	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if ( err == nil ) {
		return jsonBody["access_token"].(string), nil
	} else {
		log.Error( "Error parsing response: " + err.Error() )
		log.Error( "Input was: " + string(resBody) )
		return "", err
	}
}

func GetTokenAPIKey( iam_url string, tenant string, api_key string ) (string, error) {
	login_url := iam_url + "/auth/realms/" + tenant + "/protocol/openid-connect/token"
	
	data := url.Values{}
	data.Set( "grant_type", "refresh_token" )
	data.Set( "client_id", "ast-app" )
	data.Set( "refresh_token", api_key )

	
	log.Info( "Authenticating with Cx1 at: "+login_url )

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add( "Content-Type", "application/x-www-form-urlencoded" )
	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}
	
	cli := &http.Client{}
	res, err := cli.Do( cx1_req );
	defer res.Body.Close()

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		log.Error( "Error: " + err.Error() )
		return "", err
	}

	log.Trace( "  received response: " + string(resBody) )
	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if ( err == nil ) {
		return jsonBody["access_token"].(string), nil
	} else {
		log.Error( "Error parsing response: " + err.Error() )
		log.Error( "Input was: " + string(resBody) )
		return "", err
	}
}



// Groups
func (c Cx1client) CreateGroup ( groupname string ) (Group, error) {
	log.Debug( "Create Group: name " + groupname  )
	data := map[string]interface{} {
		"name" : groupname,
	}
	

	response, err := c.postIAM( "/auth/admin/realms/", "/groups", data )
    if err != nil {
        log.Error( "Error creating group: " + err.Error() )
        return Group{}, nil
    }

	log.Trace( " - response: " + response )
	return c.GetGroupByName( groupname )
}

func (c *Cx1client) GetGroups () ([]Group, error) {
	log.Debug( "Get Groups" )
    var Groups []Group
	
    response, err := c.getIAM( "/auth/admin/realms/", "/groups?briefRepresentation=true" )
    if err != nil {
        return Groups, err
    }

    Groups, err = parseGroups( response )
    log.Trace( "Got " + strconv.Itoa( len(Groups) ) + " groups" )
    return Groups, err
}

func (c Cx1client) GetGroupByName (groupname string) (Group, error) {
	log.Debug( "Get Group by name: " + groupname )
    response, err := c.getIAM( "/auth/admin/realms/", "/groups?briefRepresentation=true&search=" + url.QueryEscape(groupname) )
    if err != nil {
        return Group{}, err
    }
	groups, err := parseGroups( response )
	
    if err != nil {
        log.Error( "Error retrieving group: " + err.Error() )
        return Group{}, err
    }

	log.Trace( "Got " + strconv.Itoa( len(groups) ) + " groups" )

	for i := range groups {
		if groups[i].Name == groupname {
			match := groups[i]
			return match, nil
		}
	}
	
	return Group{}, errors.New( "No matching group found" )
}



func (c *Cx1client) GetPresets () ([]Preset, error) {
	log.Debug( "Get Presets" )
    var Presets []Preset
    response, err := c.get( "/api/queries/presets" )
    if err != nil {
        return Presets, err
    }

    Presets, err = parsePresets( response )
    log.Trace( "Got " + strconv.Itoa( len(Presets) ) + " presets" )
    return Presets, err
}





// Projects
func (c Cx1client) CreateProject ( projectname string, cx1_group_id string, tags map[string]string ) (Project,error) {
	log.Debug ( "Create Project: name " + projectname + ", group id " + cx1_group_id )
	data := map[string]interface{} {
		"name" : projectname,
		"groups" : []string{ cx1_group_id },
		"tags" : tags,
		"criticality" : 3,
		"origin" : "SAST2Cx1",
	}

    var project Project
	response, err := c.post( "/api/projects", data )
	if err != nil {
		log.Info( " - response: " + response )
        log.Error( "Error while creating project: " + err.Error() )
        return project, err
	}
    
    err = json.Unmarshal( []byte( response ), &project )        

	return project, err
}

func (c *Cx1client) GetProjects () ([]Project, error) {
	log.Debug( "Get Projects" )
    var Projects []Project
	
    response, err := c.get( "/api/projects/" )
    if err != nil {
        return Projects, err
    }

    Projects, err = parseProjects( response )
    log.Trace( "Retrieved " + strconv.Itoa( len(Projects) ) + " projects")
    return Projects, err
	
}

func (c Cx1client) GetProjectByName ( projectname string ) (Project,error) {
	log.Debug( "Get Project By Name: " + projectname )
    response, err := c.get( "/api/projects?name=" + url.QueryEscape(projectname) )
    if err != nil {
        return Project{}, err
    }

	projects, err := parseProjects( response )
    if err != nil {
        log.Error( "Error getting project: " + err.Error() )
        return Project{}, err
    }

	log.Trace( "Got " + strconv.Itoa( len(projects) ) + " projects" )

	for i := range projects {
		if projects[i].Name == projectname {
			match := projects[i]
			return match, nil
		}
	}

	return Project{}, errors.New( "No such project found" )
}



func (c *Cx1client) GetQueries () ([]Query, error) {
	log.Debug( "Get Queries" )
    var Queries []Query

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
	//c.Queries = parseQueries( c.get( "/api/queries" ) )

	return Queries, nil
}

// Scans
// GetScans returns all scan status on the project addressed by projectID
// todo cleanup systeminstance
func (c *Cx1client) GetScan(scanID string) (Scan, error) {
    var scan Scan

    data, err := c.get( fmt.Sprintf("/scans/%v", scanID) )
    if err != nil {
        log.Errorf("Failed to fetch scan with ID %v: %s", scanID, err)
        return scan, errors.Wrapf(err, "failed to fetch scan with ID %v", scanID)
    }

    json.Unmarshal( []byte(data), &scan)
    return scan, nil
}



func (c Cx1client) GetUploadURL () (string,error) {
	log.Debug( "Get Upload URL" )
	data := make( map[string]interface{}, 0 )
	response, err := c.post( "/api/uploads", data )

    if err != nil {
        log.Error( "Unable to get URL: " + err.Error() )
        return "", err
    } 

	var jsonBody map[string]interface{}

	err = json.Unmarshal( []byte( response ), &jsonBody )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + response )
		return "", err
	} else {
		return jsonBody["url"].(string), nil
	}
}




func (c *Cx1client) GetUsers () ([]User, error) {
	log.Debug( "Get Users" )

    var Users []User
    // Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
    response, err := c.getIAM( "/auth/admin/realms/", "/users?briefRepresentation=true" )
    if err != nil {
        return Users, err
    }

    Users, err = parseUsers( response )
    log.Trace( "Got " + strconv.Itoa( len(Users) ) + " users" )
    return Users, err 
}



func (c Cx1client) ToString() string {
	return c.tenant + " on " + c.baseUrl
}



func (c Cx1client) StartZipScan( projectId string, uploadUrl string, tags map[string]string ) (RunningScan,error) {
	log.Debug( "Starting a zip scan for project " + projectId + " with URL " + uploadUrl )
	body := map[string]interface{}{
		"project" : map[string]interface{}{	"id" : projectId },
		"type": "upload",
		"tags": tags,
		"handler" : map[string]interface{}{ "uploadurl" : uploadUrl },
		"config" : []map[string]interface{}{
			map[string]interface{}{
				"type" : "sast",
				"value" : map[string]interface{}{
					"incremental" : "false",
					"presetName": "Checkmarx Default",
				},
			},
		},
	}

	response, err := c.post( "/api/scans", body )
	if err != nil {
		log.Error( "Failed to start a scan")
		return RunningScan{}, err
	}

	log.Debug( "Received response: " + response )
	
	var scan map[string]interface{}

	err = json.Unmarshal( []byte( response ), &scan )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + response )
		return RunningScan{}, err
	} else {
		return parseRunningScanFromInterface( &scan )        
	}
}


// internal data-parsing

func parseGroups( input string ) ([]Group, error) {
	log.Trace( "Parsing groups from: " + input )
	var groups []interface{}

	var groupList []Group

	err := json.Unmarshal( []byte( input ), &groups )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + input )
		return groupList, err
	} else {
		groupList = make([]Group, len(groups) )
		for id := range groups {
			groupList[id].GroupID = groups[id].(map[string]interface{})["id"].(string)
			groupList[id].Name = groups[id].(map[string]interface{})["name"].(string)

		}
	}

	return groupList, nil
}



func parsePresets( input string ) ([]Preset, error) {
	log.Trace( "Parsing presets from: " + input )

	var presets []Preset
    var presetResponse []map[string]interface{}
    var err error

    err = json.Unmarshal( []byte( input ), &presetResponse )
    if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + input )
		return presets, err
	}

    presets = make( []Preset, len(presetResponse) )

    for id, p := range presetResponse {
        //log.Debug( " - " + strconv.Itoa( int(p["id"].(float64)) ) + ": " + p["name"].(string) )
        presets[id].PresetID = int(p["id"].(float64))
        presets[id].Name = p["name"].(string)
    }



    //log.Trace( "Preset1: " + presets[0].PresetID + ", " + preset[0].Name )

	return presets, nil

}

func parseProjects( input string ) ([]Project, error) {
	log.Trace( "Parsing projects from: " + input )
	var projectResponse struct {
        TotalCount int
        filteredTotalCount int
        Projects []interface{}
    }
    var projectList []Project

	err := json.Unmarshal( []byte( input ), &projectResponse )
	if err != nil {
		log.Error("Error: " + err.Error() )
		return projectList, err
	}

	projects := projectResponse.Projects

	projectList = make([]Project, len(projects) )
	for id := range projects {
		projectList[id].ProjectID = projects[id].(map[string]interface{})["id"].(string)
		projectList[id].Name = projects[id].(map[string]interface{})["name"].(string)
	}
	

	return projectList, nil
}

func parseRunningScans( input string ) ([]RunningScan,error) {
	var scans []RunningScan

	//var scanList []interface{} TODO
	
	return scans, nil
}

func parseRunningScanFromInterface( input *map[string]interface{} ) (RunningScan, error) {
	log.Trace( "Parsing scan from interface" )
	scan := RunningScan{}

	scan.ScanID = (*input)["id"].(string)
	scan.ProjectID = (*input)["projectId"].(string)
	scan.Status = (*input)["status"].(string)

	var err error
    var err2 error

	scan.CreatedAt, err = time.Parse(time.RFC3339, (*input)["createdAt"].(string) )

	if err != nil {
		log.Warn( "Failed to parse time from " + (*input)["createdAt"].(string) )
	}



	scan.UpdatedAt, err2 = time.Parse(time.RFC3339, (*input)["updatedAt"].(string) )

	if err2 != nil {
		log.Warn( "Failed to parse time from " + (*input)["updatedAt"].(string) )
        err = errors.Wrap( err, err2.Error() )
	}

	return scan, err
}

func parseUsers( input string ) ([]User, error) {
	log.Trace( "Parsing users from: " + input )
	var users []map[string]interface{}

	var userList []User

	err := json.Unmarshal( []byte( input ), &users )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + input )
		return userList, err
	} else {
		userList = make([]User, 0 )
		
		for _, u := range users {
			user, err := parseUserFromInterface( &u )			
			if err != nil {
                log.Error("Failed to parse user: " + err.Error() )

            } else {
				userList = append( userList, user )
			}
		}
	}

	return userList, nil
}

func parseUserFromInterface( input *map[string]interface{} ) (User, error) {
	log.Trace( "Parsing user from interface" )
    var user User

	if (*input)["id"] == nil {
		return user, errors.New( "No id variable in input" )
	}

	user.UserID = (*input)["id"].(string)

	if (*input)["firstName"] != nil {
		user.FirstName = (*input)["firstName"].(string)
	}

	if (*input)["lastName"] != nil {	
		user.LastName = (*input)["lastName"].(string)
	}

	user.UserName = (*input)["username"].(string)

	return user, nil
}

