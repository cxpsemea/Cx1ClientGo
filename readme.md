# Repository Update
This repository will remain public but will be moving to a new location in the future. 
More details around the timeline will be shared as soon as they are available - apologies for the inconvenience.


## Module information
This is a basic CheckmarxOne REST API client written in GoLang. 

Basic usage:

```golang
package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"
	"os"
    "net/http"
)

func main() {
	logger := log.New()
	logger.Infof( "Starting" )
	cx1client, err := Cx1ClientGo.NewClient(&http.Client{}, logger)
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}

	// no err means that the client is initialized
	logger.Infof( "Client initialized: " + cx1client.ToString() )
}
```

Using the NewClient function includes command-line arguments - the above example will include output help on command-line arguments when executed:
```
> go run . -h
[INFO][2025-11-11 14:00:57.344] Starting
Usage of C:\..\cx1test.exe:
  -apikey string
        CheckmarxOne API Key (if not using client id/secret)
  -client string
        CheckmarxOne Client ID (if not using API Key)
  -cx1 string
        Optional: CheckmarxOne platform URL, if not defined in the test config.yaml
  -iam string
        Optional: CheckmarxOne IAM URL, if not defined in the test config.yaml
  -secret string
        CheckmarxOne Client Secret (if not using API Key)
  -tenant string
        Optional: CheckmarxOne tenant, if not defined in the test config.yaml
```


More complete workflow example:

```golang
package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
	"net/http"
	"net/url"
	"crypto/tls"
)

func main() {
	logger := log.New()
	logger.Infof( "Starting" )
	//logger.SetLevel( log.TraceLevel ) 

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]
	project_name := os.Args[5]
	group_name := os.Args[6]
	project_repo := os.Args[7]
	branch_name := os.Args[8]
	
	proxyURL, err := url.Parse( "http://127.0.0.1:8080" )
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{ InsecureSkipVerify: true, }
	
	httpClient := &http.Client{}
	//httpClient.Transport = transport
	
	
	cx1client, err := Cx1ClientGo.NewAPIKeyClient( httpClient, base_url, iam_url, tenant, api_key, logger )
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}

	// no err means that the client is initialized
	logger.Infof( "Client initialized: " + cx1client.ToString() )
	
	group, err := cx1client.GetGroupByName( group_name )
	if err != nil {
		if err.Error() != "No matching group found" {
			logger.Infof( "Failed to retrieve group named %s: %v", group_name, err )
			return
		}
		
		logger.Infof( "No group named %s exists - it will now be created", group_name )
		group, err = cx1client.CreateGroup( group_name )
		if err != nil {
			logger.Errorf( "Failed to create group %s: %v", group_name, err )
			return
		}
		
		logger.Infof( "Created group named '%v' with ID %v", group.Name, group.GroupID )
	} else {	
		logger.Infof( "Found group named %v with ID %v", group.Name, group.GroupID )
	}
	
	projects, err := cx1client.GetProjectsByNameAndGroup( project_name, group.GroupID )
	if err != nil {
		logger.Errorf( "Failed to retrieve project named %s: %v", project_name, err )
		return
	}	
	
	var project Cx1ClientGo.Project
	if len(projects) == 0 {
		logger.Infof( "No project named %s found under group %s - it will now be created", project_name, group_name )
		project, err = cx1client.CreateProject( project_name, group.GroupID, map[string]string{ "CreatedBy" : "Cx1ClientGo" } )
		if err != nil {
			logger.Errorf( "Failed to create project %s: %v", project_name, err )
			return
		}
		logger.Infof( "Created project named '%v' with ID %v", project.Name, project.ProjectID )
	} else {
		project = projects[0]
		logger.Infof( "First project matching '%v' in group '%v' is named '%v' with ID %v", project_name, group_name, project.Name, project.ProjectID )
	}
	
	scanConfig := Cx1ClientGo.ScanConfiguration{}
	scanConfig.ScanType = "sast"
	scanConfig.Values = map[string]string{ "incremental" : "false" }
	
	scan, err := cx1client.ScanProjectGitByID( project.ProjectID, project_repo, branch_name, []Cx1ClientGo.ScanConfiguration{scanConfig}, map[string]string{ "CreatedBy" : "Cx1ClientGo" } )
	
	if err != nil {
		logger.Errorf( "Failed to trigger scan with repository '%v' branch '%v': %s", project_repo, branch_name, err )
		return
	}
	
	logger.Infof( "Triggered scan %v, polling status", scan.ScanID )
	for scan.Status == "Running" {
		time.Sleep( 10 * time.Second )
		scan, err = cx1client.GetScanByID( scan.ScanID )
		if err != nil {
			logger.Errorf( "Failed to get scan status: %v", err )
			return
		}
		logger.Infof( " - %v", scan.Status )
	}
	
	reportID, err := cx1client.RequestNewReportByID( scan.ScanID, project.ProjectID, branch_name, "pdf" )
	if err != nil {
		logger.Errorf( "Failed to trigger new report generation for scan ID %v, project ID %v: %s", scan.ScanID, project.ProjectID, err )
		return
	}
	
	logger.Infof( "Generating report %v, polling status", reportID )
	var status Cx1ClientGo.ReportStatus
	
	for status.Status != "completed" {
		time.Sleep( 10 * time.Second )
		status, err = cx1client.GetReportStatusByID( reportID )
		if err != nil {
			logger.Errorf( "Failed to get report status: %v", err )
			return
		}
		
		logger.Infof( " - %v", status.Status )
	}
	
	logger.Infof( "Downloading report from %v", status.ReportURL )
	reportData, err := cx1client.DownloadReport( status.ReportURL )
	if err != nil {
		logger.Errorf( "Failed to download report: %s", err )
		return
	}
	
	err = os.WriteFile( "report.pdf", reportData, 0o700 )
	if err != nil {
		logger.Errorf( "Failed to Update report: %s", err )
		return
	}
	logger.Infof( "Report Updated to report.pdf" )
	
	scanresults, err := cx1client.GetScanResultsByID( scan.ScanID )
	if err != nil && len(scanresults) == 0 {
		logger.Errorf( "Failed to retrieve scan results: %s", err )
		return
	}
	
	if err != nil {
		logger.Infof( "Results retrieved but error thrown: %s", err ) // can be "remote error: tls: user canceled" but still returns results
	} else {
		logger.Infof( "%d results retrieved", len(scanresults) )
	}
	
	for _, result := range scanresults {
		logger.Infof( "Finding with similarity ID: %v", result.SimilarityID )
	}
}
```

Invocation for the more complicated example:
go run . "https://eu.ast.checkmarx.net" "https://eu.iam.checkmarx.net" "tenant" "API Key" "Project Name" "Group Name" "https://my.github/project/repo" "branch"


Note that the Cx1ClientGo library is not an official Checkmarx product and does not include any guarantees of support or future improvements. 
It is a library built to facilitate delivering custom development work on integrations with the CheckmarxOne platform.