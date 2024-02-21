package main

import (
	"embed"
	"errors"
	"flag"
	"github.com/1f349/mjwt"
	"github.com/1f349/orchid"
	"github.com/1f349/orchid/agent"
	httpAcme "github.com/1f349/orchid/http-acme"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/renewal"
	"github.com/1f349/orchid/servers"
	"github.com/1f349/overlapfs"
	"github.com/1f349/simplemail"
	"github.com/1f349/violet/utils"
	_ "github.com/mattn/go-sqlite3"
	exitReload "github.com/mrmelon54/exit-reload"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

var configPath string

//go:embed mail-templates/*
var mailTemplates embed.FS

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

	// get mail templates
	mailDir := filepath.Join(wd, "mail-templates")
	err = os.Mkdir(mailDir, os.ModePerm)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return
	}
	wdFs := os.DirFS(mailDir)
	mailTemplatesSub, err := fs.Sub(mailTemplates, "mail-templates")
	if err != nil {
		logger.Logger.Fatal("Failed to load embedded mail templates", "err", err)
	}
	templatesFS := overlapfs.OverlapFS{A: mailTemplatesSub, B: wdFs}

	mail, err := simplemail.New(&conf.Mail.Mail, templatesFS)
	if err != nil {
		logger.Logger.Fatal("Failed to load email sender", "err", err)
	}

	// open sqlite database
	db, err := orchid.InitDB(filepath.Join(wd, "orchid.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	certDir := filepath.Join(wd, "renewal-certs")
	keyDir := filepath.Join(wd, "renewal-keys")

	wg := new(sync.WaitGroup)
	acmeProv, err := httpAcme.NewHttpAcmeProvider(filepath.Join(wd, "tokens.yml"), conf.Acme.PresentUrl, conf.Acme.CleanUpUrl, conf.Acme.RefreshUrl)
	if err != nil {
		logger.Logger.Fatal("HTTP Acme Error", "err", err)
	}
	renewalService, err := renewal.NewService(wg, db, acmeProv, conf.LE, certDir, keyDir, mail, conf.Mail.To)
	if err != nil {
		logger.Logger.Fatal("Service Error", "err", err)
	}
	certAgent, err := agent.NewAgent(wg, db, loadAgentPrivateKey(wd), certDir, keyDir)
	if err != nil {
		logger.Logger.Fatal("Failed to create agent", "err", err)
	}
	srv := servers.NewApiServer(conf.Listen, db, mJwtVerify, conf.Domains)
	logger.Logger.Info("Starting API server", "listen", srv.Addr)
	go utils.RunBackgroundHttp(logger.Logger, srv)

	exitReload.ExitReload("Violet", func() {}, func() {
		// stop renewal service and api server
		renewalService.Shutdown()
		certAgent.Shutdown()
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
