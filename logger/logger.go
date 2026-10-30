package logger

import (
	"charm.land/log/v2"
	"os"
)

var Logger = log.NewWithOptions(os.Stderr, log.Options{
	ReportCaller:    true,
	ReportTimestamp: true,
	Prefix:          "Orchid",
})
