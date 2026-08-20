package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

// Reporting demonstrates the Report/Export object type, which none of the other
// concept demos touch:
//   - creating a Project that lives directly under the tenant, with no Application
//     at all (contrast with OneHundredApps/QueryManipulation, which both use one)
//   - running a single scan with several engines enabled at once
//   - the scan-level and project-level report request -> poll -> download cycle,
//     using both the older "v1" report API and the newer "v2" report API
//   - the SCA-specific SBOM export cycle, and using a downloaded SBOM as the source
//     for a separate scan (as opposed to a git repo or an uploaded archive)
//
// Scan engines available on the platform (not all are exposed for editing via this
// library, but every one of them can be enabled on a scan via ScanConfigurationSet):
// "sast", "sca", "iac" (aka "kics"), "containers", "apisec", and "2ms" (aka "secrets",
// the Enterprise Secrets micro-engine). This example enables a representative subset;
// see configurationsettings.go for the per-engine configuration keys this library
// knows how to set individually.
func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	logger.Infof("Starting")

	httpClient := &http.Client{}
	cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	project, scan, err := runMultiEngineScan(cx1client, logger)
	if err != nil {
		logger.Fatalf("Failed to run multi-engine scan: %s", err)
	}

	generateReports(cx1client, logger, project, scan)
	sbomExportAndRescan(cx1client, logger, scan.ScanID)

	logger.Infof("Done")
}

// A Project doesn't need an Application to exist - it can live directly under the
// tenant. GetOrCreateProjectByName (no application argument) is idempotent, same as
// the Application-scoped GetOrCreateProjectInApplicationByName used elsewhere.
func runMultiEngineScan(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) (Cx1ClientGo.Project, Cx1ClientGo.Scan, error) {
	project, err := cx1client.GetOrCreateProjectByName("reporting-example")
	if err != nil {
		return project, Cx1ClientGo.Scan{}, fmt.Errorf("failed to get or create project: %s", err)
	}
	logger.Infof("Got project: %v", project.String())

	scanConfig := Cx1ClientGo.ScanConfigurationSet{}
	// AddScanEngine turns an engine on with its defaults; AddConfig (used elsewhere,
	// e.g. QueryManipulation) additionally sets a specific key on that engine.
	scanConfig.AddScanEngine("sast")
	scanConfig.AddScanEngine("sca")
	scanConfig.AddScanEngine("iac") // translated internally to "kics"

	scan, err := cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/GitHubSecurityLab/hackers-first-workshop", "main", scanConfig.Configurations, map[string]string{})
	if err != nil {
		return project, scan, fmt.Errorf("failed to start scan: %s", err)
	}
	logger.Infof("Started scan: %v", scan.String())

	scan, err = cx1client.ScanPollingDetailed(&scan)
	if err != nil {
		return project, scan, fmt.Errorf("scan failed: %s", err)
	}
	logger.Infof("Scan completed: %v", scan.String())

	return project, scan, nil
}

// Reports are asynchronous, same shape as MigrationImport's import polling: request,
// poll for a terminal status, then download. Unlike an import, a report request also
// needs to pick a report type (v1: "ui"/"pdf"/"csv"/etc. file formats via
// RequestNewReportByID; v2: a structured ReportRequest via RequestNewReportByIDsv2 or
// its scan/project convenience wrappers) and which engines/sections to include.
func generateReports(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, project Cx1ClientGo.Project, scan Cx1ClientGo.Scan) {
	engines := []string{"sast", "sca", "kics"}

	// v1 API: scan-level report, tied to one specific scan + branch.
	reportID, err := cx1client.RequestNewReportByID(scan.ScanID, project.ProjectID, scan.Branch, "pdf", engines, []string{"ScanSummary", "ExecutiveSummary", "ScanResults"})
	if err != nil {
		logger.Errorf("Failed to request v1 scan report: %s", err)
	} else {
		pollAndSaveReport(cx1client, logger, reportID, "v1-scan-report.pdf")
	}

	// v2 API: also scan-level, but with a richer set of sections/severities/states
	// baked in by RequestNewReportByScanIDv2 - see reports.go for the exact defaults.
	reportID, err = cx1client.RequestNewReportByScanIDv2(scan.ScanID, engines, []string{}, []string{}, "pdf")
	if err != nil {
		logger.Errorf("Failed to request v2 scan report: %s", err)
	} else {
		pollAndSaveReport(cx1client, logger, reportID, "v2-scan-report.pdf")
	}

	// v2 API: project-level instead of scan-level. This variant takes no branch at
	// all and can aggregate multiple project IDs into a single report - here we pass
	// just the one project, which is also why this example didn't need an
	// Application: project-level reports don't require one either.
	reportID, err = cx1client.RequestNewReportByProjectIDv2([]string{project.ProjectID}, engines, []string{}, []string{}, "pdf")
	if err != nil {
		logger.Errorf("Failed to request v2 project report: %s", err)
	} else {
		pollAndSaveReport(cx1client, logger, reportID, "v2-project-report.pdf")
	}
}

func pollAndSaveReport(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, reportID, filename string) {
	reportUrl, err := cx1client.ReportPollingByID(reportID)
	if err != nil {
		logger.Errorf("Failed to poll report %v: %s", reportID, err)
		return
	}

	data, err := cx1client.DownloadReport(reportUrl)
	if err != nil {
		logger.Errorf("Failed to download report %v: %s", reportID, err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		logger.Errorf("Failed to save report to %v: %s", filename, err)
		return
	}
	logger.Infof("Saved report to %v (%d bytes)", filename, len(data))
}

// The SCA export/SBOM cycle uses its own request -> poll -> download trio
// (RequestNewExportByID / ExportPollingByID / DownloadExport) that's entirely
// separate from the Report ones above - it lives under /sca/export rather than
// /reports, and there's no v1/v2 split. Once downloaded, an SBOM isn't just an
// artifact to keep: it can be fed straight back in as the source for a new scan
// (ScanProjectSBOMByID) instead of a git repo or an uploaded source archive.
func sbomExportAndRescan(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, scanID string) {
	for _, sbomFormat := range []string{"CycloneDxjson", "CycloneDxxml", "Spdxjson"} {
		fileType := "json"
		if strings.HasSuffix(sbomFormat, "xml") {
			fileType = "xml"
		}

		exportID, err := cx1client.RequestNewExportByID(scanID, sbomFormat, false, false, false)
		if err != nil {
			logger.Errorf("Failed to request %v SBOM export: %s", sbomFormat, err)
			continue
		}

		exportUrl, err := cx1client.ExportPollingByID(exportID)
		if err != nil {
			logger.Errorf("Failed to poll %v SBOM export: %s", sbomFormat, err)
			continue
		}

		sbom, err := cx1client.DownloadExport(exportUrl)
		if err != nil {
			logger.Errorf("Failed to download %v SBOM export: %s", sbomFormat, err)
			continue
		}
		logger.Infof("Downloaded %v SBOM: %d bytes", sbomFormat, len(sbom))

		sbomProject, err := cx1client.GetOrCreateProjectByName("reporting-example-sbom-rescan")
		if err != nil {
			logger.Errorf("Failed to get or create SBOM rescan project: %s", err)
			continue
		}

		uploadUrl, err := cx1client.UploadBytes(&sbom)
		if err != nil {
			logger.Errorf("Failed to upload SBOM bytes: %s", err)
			continue
		}

		sbomScan, err := cx1client.ScanProjectSBOMByID(sbomProject.ProjectID, uploadUrl, "sbom-rescan", fileType, map[string]string{})
		if err != nil {
			logger.Errorf("Failed to trigger SBOM scan from %v export: %s", sbomFormat, err)
			continue
		}

		sbomScan, err = cx1client.ScanPollingDetailed(&sbomScan)
		if err != nil {
			logger.Errorf("SBOM rescan (from %v export) failed: %s", sbomFormat, err)
			continue
		}
		logger.Infof("SBOM rescan (from %v export) completed: %v", sbomFormat, sbomScan.String())
	}
}
