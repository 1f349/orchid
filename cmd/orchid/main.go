package main

import (
	"flag"
	"github.com/1f349/mjwt"
	"github.com/1f349/orchid"
	httpAcme "github.com/1f349/orchid/http-acme"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/renewal"
	"github.com/1f349/orchid/servers"
	"github.com/1f349/violet/utils"
	_ "github.com/mattn/go-sqlite3"
	exitReload "github.com/mrmelon54/exit-reload"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sync"
)

var configPath string

func main() {
	flag.StringVar(&configPath, "conf", "", "/path/to/config.json : path to the config file")
	flag.Parse()

	logger.Logger.Info("Starting...")

	if configPath == "" {
		logger.Logger.Error("Config flag is missing")
		trySetup(configPath)
		return
	}

	wd, err := getWD(configPath)
	if err != nil {
		logger.Logger.Fatal("Failed to find config directory", "err", err)
	}

	// try to open the config file
	openConf, err := os.Open(configPath)
	switch {
	case err == nil:
		break
	case os.IsNotExist(err):
		logger.Logger.Warn("Failed to open config file", "err", err)
		trySetup(wd)
		return
	default:
		logger.Logger.Fatal("Open config file", "err", err)
	}

	// config file opened with no errors

	defer openConf.Close()

	var config startUpConfig
	err = yaml.NewDecoder(openConf).Decode(&config)
	if err != nil {
		logger.Logger.Fatal("Invalid config file", "err", err)
	}

	runDaemon(wd, config)
}

func runDaemon(wd string, conf startUpConfig) {
	// load the MJWT RSA public key from a pem encoded file
	mJwtVerify, err := mjwt.NewKeyStoreFromPath(filepath.Join(wd, "keys"))
	if err != nil {
		logger.Logger.Fatal("Failed to load MJWT verifier public key from file", "path", filepath.Join(wd, "keys"), "err", err)
	}

	// open sqlite database
	db, err := orchid.InitDB(filepath.Join(wd, "orchid.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	certDir := filepath.Join(wd, "renewal-certs")
	keyDir := filepath.Join(wd, "renewal-keys")

	wg := &sync.WaitGroup{}
	acmeProv, err := httpAcme.NewHttpAcmeProvider(filepath.Join(wd, "tokens.yml"), conf.Acme.PresentUrl, conf.Acme.CleanUpUrl, conf.Acme.RefreshUrl)
	if err != nil {
		logger.Logger.Fatal("HTTP Acme Error", "err", err)
	}
	renewalService, err := renewal.NewService(wg, db, acmeProv, conf.LE, certDir, keyDir)
	if err != nil {
		logger.Logger.Fatal("Service Error", "err", err)
	}
	srv := servers.NewApiServer(conf.Listen, db, mJwtVerify, conf.Domains)
	logger.Logger.Info("Starting API server", "listen", srv.Addr)
	go utils.RunBackgroundHttp(logger.Logger, srv)

	exitReload.ExitReload("Violet", func() {}, func() {
		// stop renewal service and api server
		renewalService.Shutdown()
		srv.Close()
	})
}

func getWD(configPath string) (string, error) {
	if configPath == "" {
		return os.Getwd()
	}
	wdAbs, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	return filepath.Dir(wdAbs), nil
}
