package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"github.com/MrMelon54/mjwt"
	"github.com/google/subcommands"
	"log"
	"os"
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
	err = json.NewDecoder(openConf).Decode(&conf)
	if err != nil {
		log.Println("[Orchid] Error: invalid config file: ", err)
		return subcommands.ExitFailure
	}

	normalLoad(conf)
	return subcommands.ExitSuccess
}

func normalLoad(conf startUpConfig) {
	os.ReadFile()
	x509.ParsePKCS1PrivateKey()
	mjwtVerify, err := mjwt.NewMJwtVerifierFromFile(conf.PubKey)
	if err != nil {

	}
}
