package main

import (
	"context"
	"flag"
	"github.com/1f349/mjwt"
	"github.com/1f349/orchid"
	httpAcme "github.com/1f349/orchid/http-acme"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/renewal"
	"github.com/1f349/orchid/servers"
	"github.com/1f349/violet/utils"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mrmelon54/exit-reload"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type serveCmd struct{ configPath string }

func (s *serveCmd) Name() string     { return "serve" }
func (s *serveCmd) Synopsis() string { return "Serve certificate renewal service" }
func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
}
func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>]
  Serve certificate renewal service using information from config file
`
}

func (s *serveCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	logger.Logger.Info("[Orchid] Starting...")

	if s.configPath == "" {
		logger.Logger.Info("[Orchid] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Logger.Info("[Orchid] Error: missing config file")
		} else {
			logger.Logger.Info("[Orchid] Error: open config file: ", "err", err)
		}
		return subcommands.ExitFailure
	}

	var conf startUpConfig
	err = yaml.NewDecoder(openConf).Decode(&conf)
	if err != nil {
		logger.Logger.Info("[Orchid] Error: invalid config file: ", "err", err)
		return subcommands.ExitFailure
	}

	wd := filepath.Dir(s.configPath)
	normalLoad(conf, wd)
	return subcommands.ExitSuccess
}

func normalLoad(conf startUpConfig, wd string) {
	// load the MJWT RSA public key from a pem encoded file
	mJwtVerify, err := mjwt.NewMJwtVerifierFromFile(filepath.Join(wd, "signer.public.pem"))
	if err != nil {
		log.Fatalf("[Orchid] Failed to load MJWT verifier public key from file '%s': %s", filepath.Join(wd, "signer.public.pem"), err)
	}

	// open sqlite database
	db, err := orchid.InitDB(filepath.Join(wd, "orchid.db.sqlite"))
	if err != nil {
		log.Fatal("[Orchid] Failed to open database:", err)
	}

	certDir := filepath.Join(wd, "certs")
	keyDir := filepath.Join(wd, "keys")

	wg := &sync.WaitGroup{}
	acmeProv, err := httpAcme.NewHttpAcmeProvider(filepath.Join(wd, "tokens.yml"), conf.Acme.PresentUrl, conf.Acme.CleanUpUrl, conf.Acme.RefreshUrl)
	if err != nil {
		log.Fatal("[Orchid] HTTP Acme Error:", err)
	}
	renewalService, err := renewal.NewService(wg, db, acmeProv, conf.LE, certDir, keyDir)
	if err != nil {
		log.Fatal("[Orchid] Service Error:", err)
	}
	srv := servers.NewApiServer(conf.Listen, db, mJwtVerify, conf.Domains)
	logger.Logger.Info("Starting API server", "listen", srv.Addr)
	go utils.RunBackgroundHttp(logger.Logger, srv)

	exit_reload.ExitReload("Violet", func() {}, func() {
		// stop renewal service and api server
		renewalService.Shutdown()
		srv.Close()
	})
}
