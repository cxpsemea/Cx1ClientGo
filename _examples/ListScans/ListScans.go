// ListScans demonstrates the ScanFilter object and the two ways to page through
// filtered scan results:
//   - parsing a comma-separated "key=value" command-line flag into a ScanFilter
//     (see makeScanFilter for the recognised keys)
//   - GetAllScansFiltered, which transparently pages through *every* matching scan
//     (used when no explicit limit/offset was requested)
//   - GetScansFiltered, which returns a single page (used when the caller supplied
//     an explicit limit and/or offset, so pagination is left in their hands)
//
// Run with e.g.:
//
//	go run . -filters projectId=X,sort=-created_at,limit=50
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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

	logger.Infof("Starting")
	filterInput := flag.String("filters", "", "Optional: Comma separated list of filters, eg: projectId=X,sort=-created_at")

	cx1Client, err := Cx1ClientGo.NewClient(&http.Client{}, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	filters := strings.Split(*filterInput, ",")

	// Turn the raw "key=value,key=value" flag into a typed ScanFilter.
	scanFilter, customPage := makeScanFilter(logger, filters)

	var count uint64
	var scans []Cx1ClientGo.Scan

	if customPage {
		// The caller asked for a specific limit/offset - fetch exactly that one page,
		// falling back to the configured default page size if no limit was given.
		if scanFilter.Limit == 0 {
			scanFilter.Limit = cx1Client.GetPaginationSettings().Scans
		}
		count, scans, err = cx1Client.GetScansFiltered(scanFilter)
	} else {
		// No explicit paging requested - fetch every matching scan across all pages.
		count, scans, err = cx1Client.GetAllScansFiltered(scanFilter)
	}

	if err != nil {
		logger.Fatalf("Error retrieving scans: %s", err)
	} else {
		logger.Infof("Retrieved %d scans", count)
	}

	for _, scan := range scans {
		fmt.Printf("%s|%s|%s|%s|%v|%s|%s|%s|%s\n", scan.ScanID,
			scan.CreatedAt, scan.ProjectName, scan.Branch,
			tagsToString(scan.Tags), scan.SourceOrigin,
			scan.SourceType, scan.Initiator, scan.Status)
	}
}

// makeScanFilter parses "key=value" pairs into a ScanFilter. customPage is set to
// true only if the caller explicitly supplied "limit" and/or "offset", which is what
// tells main() to fetch a single page instead of every matching scan.
func makeScanFilter(logger *logrus.Logger, filters []string) (scanFilter Cx1ClientGo.ScanFilter, customPage bool) {
	for _, filter := range filters {
		parts := strings.SplitN(filter, "=", 2)
		if len(parts) != 2 {
			logger.Errorf("%s: malformed filter", filter)
		} else {
			switch strings.ToLower(parts[0]) {
			case "projectid":
				scanFilter.ProjectID = parts[1]
			case "limit":
				limit, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					logger.Errorf("%s: cannot convert to integer: %s",
						parts[1], err.Error())
				} else {
					scanFilter.Limit = limit
					customPage = true
				}
			case "offset":
				offset, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					logger.Errorf("%s: cannot convert to integer: %s",
						parts[1], err.Error())
				} else {
					scanFilter.Offset = offset
					customPage = true
				}
			case "sort":
				scanFilter.Sort = []string{parts[1]}
			case "tagkeys":
				scanFilter.TagKeys = strings.Split(parts[1], ",")
			case "tagvalues":
				scanFilter.TagValues = strings.Split(parts[1], ",")
			case "statuses":
				scanFilter.Statuses = strings.Split(parts[1], ",")
			case "branches":
				scanFilter.Branches = strings.Split(parts[1], ",")
			case "fromdate":
				t, err := time.Parse(time.DateOnly, parts[1])
				if err != nil {
					logger.Errorf("%s: cannot parse date: %s",
						parts[1], err.Error())
				} else {
					scanFilter.FromDate = t
				}
			case "todate":
				t, err := time.Parse(time.DateOnly, parts[1])
				if err != nil {
					logger.Errorf("%s: cannot parse date: %s",
						parts[1], err.Error())
				} else {
					scanFilter.ToDate = t
				}
			default:
				logger.Errorf("%s: unrecognised filter", parts[0])
			}
		}
	}

	return
}

// tagsToString flattens a scan's tag map into a "key:value,key:value" string for
// the single-line, |-delimited console output produced in main().
func tagsToString(tags map[string]string) string {
	items := make([]string, 0)
	for key, value := range tags {
		if value != "" {
			items = append(items, fmt.Sprintf("%s:%s", key, value))
		} else {
			items = append(items, key)
		}
	}

	return strings.Join(items, ",")
}
