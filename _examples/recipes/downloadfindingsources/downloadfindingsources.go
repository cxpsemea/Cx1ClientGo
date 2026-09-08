// downloadfindingsources demonstrates pulling the source snippet behind
// every finding in a batch of scans and mirroring it to a local
// directory tree - useful for offline review, archival, or feeding
// findings into another tool that wants plain files rather than API
// calls.
//
// Two details matter here: dedup (several findings in the same scan
// often point at the same file, so it's only fetched once) and a small
// pause between scans so a large batch doesn't hammer the API.
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	cx1client, err := Cx1ClientGo.NewClient(&http.Client{}, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	// In a real script these would come from a file or a prior "list
	// scans" call; a short literal list keeps this recipe self-contained.
	scanIDs := []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
	}

	for i, scanID := range scanIDs {
		if err := downloadScanSources(cx1client, logger, scanID, "./output"); err != nil {
			logger.Errorf("Failed to download sources for scan %v: %s", scanID, err)
		}

		if i < len(scanIDs)-1 {
			time.Sleep(2 * time.Second) // simple throttle between scans
		}
	}
}

// downloadScanSources fetches the IAC results for one scan and writes
// the source file behind each unique finding location to
// <outputDir>/<scanID>/<path-within-repo>.
func downloadScanSources(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, scanID, outputDir string) error {
	results, err := cx1client.GetAllScanResultsByID(scanID)
	if err != nil {
		return err
	}

	scanDir := filepath.Join(outputDir, scanID)
	downloaded := make(map[string]bool)

	for _, r := range results.IAC {
		path := r.Data.FileName
		if path == "" || downloaded[path] {
			continue
		}
		downloaded[path] = true

		source, err := cx1client.GetScannedFileSourceByID(scanID, path)
		if err != nil {
			logger.Warnf("Failed to fetch source for %v in scan %v: %s", path, scanID, err)
			continue
		}

		dest := filepath.Join(scanDir, path)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			logger.Warnf("Failed to create directory for %v: %s", dest, err)
			continue
		}
		if err := os.WriteFile(dest, []byte(source), 0644); err != nil {
			logger.Warnf("Failed to write %v: %s", dest, err)
			continue
		}
	}

	logger.Infof("Downloaded %d unique source file(s) for scan %v", len(downloaded), scanID)
	return nil
}
