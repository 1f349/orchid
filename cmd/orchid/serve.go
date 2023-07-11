package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"github.com/MrMelon54/mjwt"
	httpAcme "github.com/MrMelon54/orchid/http-acme"
	"github.com/MrMelon54/orchid/renewal"
	"github.com/MrMelon54/orchid/servers"
	"github.com/MrMelon54/violet/utils"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
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
	log.Println("[Orchid] Starting...")

	if s.configPath == "" {
		log.Println("[Orchid] Error: config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[Orchid] Error: missing config file")
		} else {
			log.Println("[Orchid] Error: open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var conf startUpConfig
	err = yaml.NewDecoder(openConf).Decode(&conf)
	if err != nil {
		log.Println("[Orchid] Error: invalid config file: ", err)
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
	db, err := sql.Open("sqlite3", filepath.Join(wd, "orchid.db.sqlite"))
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
	log.Printf("[API] Starting API server on: '%s'\n", srv.Addr)
	go utils.RunBackgroundHttp("API", srv)

	// Wait for exit signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc
	fmt.Println()

	// Stop servers
	log.Printf("[Orchid] Stopping...")
	n := time.Now()

	// stop renewal service and api server
	renewalService.Shutdown()
	srv.Close()

	log.Printf("[Orchid] Took '%s' to shutdown\n", time.Now().Sub(n))
	log.Println("[Orchid] Goodbye")
}
