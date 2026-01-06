package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c *Cx1Client) StartMigration(dataArchive, projectMapping []byte, encryptionKey string) (string, error) {
	dataUrl, err := c.UploadBytes(&dataArchive)
	if err != nil {
		return "", fmt.Errorf("error uploading migration data: %s", err)
	}

	c.config.Logger.Debugf("Uploaded data archive to %v", dataUrl)
	dataFilename := getFilenameFromURL(dataUrl)

	mappingFilename := ""
	if len(projectMapping) != 0 {

		mappingUrl, err := c.UploadBytes(&projectMapping)
		mappingFilename = getFilenameFromURL(mappingUrl)
		if err != nil {
			return "", fmt.Errorf("error uploading project mapping data: %s", err)
		}

		c.config.Logger.Debugf("Uploaded project mapping to %v", mappingUrl)
	}

	return c.StartImport(dataFilename, mappingFilename, encryptionKey)
}

func (c *Cx1Client) StartImport(dataFilename, mappingFilename, encryptionKey string) (string, error) {
	jsonBody := map[string]interface{}{
		"fileName":                dataFilename,
		"projectsMappingFileName": mappingFilename,
		"encryptionKey":           encryptionKey,
	}

	body, _ := json.Marshal(jsonBody)
	response, err := c.sendRequest(http.MethodPost, "/imports", bytes.NewReader(body), nil)
	if err != nil {
		return "", err
	}

	var responseBody struct {
		MigrationId string `json:"migrationId"`
	}
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return "", err
	}

	return responseBody.MigrationId, nil
}

func (c *Cx1Client) GetImports() ([]DataImport, error) {
	response, err := c.sendRequest(http.MethodGet, "/imports", nil, nil)
	var imports []DataImport
	if err != nil {
		return imports, err
	}

	err = json.Unmarshal(response, &imports)
	return imports, err
}

func (c *Cx1Client) GetImportByID(importID string) (DataImport, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/imports/%v", importID), nil, nil)
	var di DataImport
	if err != nil {
		return di, err
	}

	err = json.Unmarshal(response, &di)
	return di, err
}

func (c *Cx1Client) GetImportLogsByID(importID string) ([]byte, error) {
	c.config.Logger.Debugf("Fetching import logs for import %v", importID)

	response, err := c.sendRequestRawCx1(http.MethodGet, fmt.Sprintf("/imports/%v/logs/download", importID), nil, nil)

	if err != nil {
		c.config.Logger.Tracef("Error retrieving import log url: %s", err)
		return []byte{}, err
	}

	importlogURL := response.Header.Get("Location")
	if importlogURL == "" {
		return []byte{}, fmt.Errorf("expected location header response not found")
	}

	c.config.Logger.Tracef("Retrieved url: %v", importlogURL)
	data, err := c.sendRequestInternal(http.MethodGet, importlogURL, nil, nil)
	if err != nil {
		c.config.Logger.Tracef("Failed to download logs from %v: %s", importlogURL, err)
		return []byte{}, nil
	}

	return data, err
}

func (c *Cx1Client) ImportPollingByID(importID string) (string, error) {
	return c.ImportPollingByIDWithTimeout(importID, c.config.Polling.MigrationPollingDelaySeconds, c.config.Polling.MigrationPollingMaxSeconds)
}

func (c *Cx1Client) ImportPollingByIDWithTimeout(importID string, delaySeconds, maxSeconds int) (string, error) {
	fail_counter := 5 // allow up to 5 failures while waiting for the import ID to be valid
	pollingCounter := 0
	for {
		status, err := c.GetImportByID(importID)
		if err == nil {
			switch status.Status {
			case "failed":
				return status.Status, fmt.Errorf("import failed: %s", status.Logs)
			case "blank":
				return status.Status, fmt.Errorf("import finished but nothing was imported: %s", status.Logs)
			case "completed":
				return status.Status, nil
			case "partial":
				return status.Status, nil
			}
			if maxSeconds != 0 && pollingCounter >= maxSeconds {
				return "timeout", fmt.Errorf("import polling reached %d seconds, aborting - use cx1client.get/setclientvars to change", pollingCounter)
			}

			c.config.Logger.Infof("Polling every %d seconds, up to %d", delaySeconds, maxSeconds)
			time.Sleep(time.Duration(delaySeconds) * time.Second)
			pollingCounter += delaySeconds
		} else {
			if err.Error()[:8] == "HTTP 404" {
				fail_counter--
				if fail_counter == 0 {
					return "", fmt.Errorf("import ID %v does not exist", importID)
				}
				c.config.Logger.Warnf("Import ID %v doesn't exist (yet) - waiting to retry %d more times", importID, fail_counter)
				time.Sleep(time.Duration(delaySeconds) * time.Second)
			} else {
				return "", err
			}
		}
	}
}

func getFilenameFromURL(url string) string {
	if ind := strings.Index(url, "?"); ind > -1 {
		url = url[:ind]
	}
	if ind := strings.LastIndex(url, "/"); ind >= -1 {
		url = url[ind+1:]
	}
	return url
}
