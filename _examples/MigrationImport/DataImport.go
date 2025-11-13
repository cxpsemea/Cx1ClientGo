package main

import (
	"flag"
	"net/http"
	"os"

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

	key := flag.String("key", "Uo9B+aCL4Z1rhemrUzUEQLCj3hX15yHxx99FQ9+vyc8=", "The encryption key for a CxSAST Export Zip file")
	file := flag.String("file", "importData.zip", "The exporter-generated zip file")
	cx1client, err := Cx1ClientGo.NewClient(&http.Client{}, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err.Error())
	}

	fileContents, err := os.ReadFile(*file)
	if err != nil {
		logger.Fatalf("Failed to read %v: %s", *file, err)
	}

	importID, err := cx1client.StartMigration(fileContents, []byte{}, *key) // no project-to-app mapping
	if err != nil {
		logger.Fatalf("Failed to start migration: %s", err)
	}

	result, err := cx1client.ImportPollingByID(importID)
	if err != nil {
		logger.Fatalf("Failed during polling: %s", err)
	}

	logger.Infof("Migration data import finished with status: %v", result)
}
