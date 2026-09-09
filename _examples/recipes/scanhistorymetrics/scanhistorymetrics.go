// scanhistorymetrics demonstrates aggregating data across a large scan
// history - larger than a single API page - using the "GetX...Filtered"
// convention: it keeps paging internally until it has gathered at least
// the requested count (or run out of matches), so callers don't have to
// write their own offset/limit loop.
//
// Here it's used to answer "what languages have we been scanning over
// the last few months", but the same pattern (bulk-beyond-one-page fetch
// + one detail call per item + aggregate into a map) applies to any
// tenant-wide metrics report.
package main

import (
	"fmt"
	"net/http"
	"os"
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

	const desiredCount = 5000

	filter := Cx1ClientGo.ScanFilter{
		BaseFilter: Cx1ClientGo.BaseFilter{Limit: cx1client.GetPaginationSettings().Scans},
		Statuses:   []string{"Completed"},
		FromDate:   time.Now().AddDate(0, -3, 0),
		Sort:       []string{"+created_at"},
	}

	count, scans, err := cx1client.GetXScansFiltered(filter, desiredCount)
	if err != nil {
		logger.Fatalf("Failed to fetch scan history: %s", err)
	}
	logger.Infof("Retrieved %d completed scans from the last 3 months", count)

	languageCounts := make(map[string]int)
	for _, scan := range scans {
		metrics, err := cx1client.GetScanMetricsByID(scan.ScanID)
		if err != nil {
			logger.Warnf("Failed to fetch metrics for scan %v: %s", scan.ScanID, err)
			continue
		}
		for _, lang := range metrics.GetLanguages() {
			languageCounts[lang]++
		}
	}

	logger.Infof("Language usage across %d scans:", len(scans))
	for lang, n := range languageCounts {
		fmt.Printf("%s: %d scans\n", lang, n)
	}
}
