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
	logger.SetLevel(logrus.TraceLevel)
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

	scanFilter, customPage := makeScanFilter(logger, filters)

	var count uint64
	var scans []Cx1ClientGo.Scan

	if customPage {
		if scanFilter.Limit == 0 {
			scanFilter.Limit = cx1Client.GetPaginationSettings().Scans
		}
		count, scans, err = cx1Client.GetScansFiltered(scanFilter)
	} else {
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
