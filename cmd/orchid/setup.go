package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	httpAcme "github.com/1f349/orchid/http-acme"
	"github.com/1f349/orchid/renewal"
	"github.com/AlecAivazis/survey/v2"
	"github.com/google/subcommands"
	"gopkg.in/yaml.v3"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type setupCmd struct{ wdPath string }

func (s *setupCmd) Name() string     { return "setup" }
func (s *setupCmd) Synopsis() string { return "Setup certificate renewal service" }
func (s *setupCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.wdPath, "wd", ".", "Path to the directory to create config files in (defaults to the working directory)")
}
func (s *setupCmd) Usage() string {
	return `setup [-wd <directory>]
  Setup Orchid automatically by answering questions.
`
}

func (s *setupCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	// get absolute path to specify files
	wdAbs, err := filepath.Abs(s.wdPath)
	if err != nil {
		fmt.Println("[Orchid] Failed to get full directory path: ", err)
		return subcommands.ExitFailure
	}

	// ask about running the setup steps
	createFile := false
	err = survey.AskOne(&survey.Confirm{Message: fmt.Sprintf("Create Orchid config files in this directory: '%s'?", wdAbs)}, &createFile)
	if err != nil {
		fmt.Println("[Orchid] Error: ", err)
		return subcommands.ExitFailure
	}
	if !createFile {
		fmt.Println("[Orchid] Goodbye")
		return subcommands.ExitSuccess
	}

	var answers struct {
		ApiListen      string
		ApiDomains     string
		AcmeRefresh    string
		AcmePresentUrl string
		AcmeCleanUpUrl string
		AcmeRefreshUrl string
		LEEmail        string
	}
	_ = answers

	// ask main questions
	err = survey.Ask([]*survey.Question{
		{
			Name:     "ApiListen",
			Prompt:   &survey.Input{Message: "API listen address", Default: "127.0.0.1:8080"},
			Validate: listenAddressValidator,
		},
		{
			Name:   "ApiDomains",
			Prompt: &survey.Input{Message: "API Domains", Help: "Comma separated list of domains which can be edited by the API"},
		},
		{
			Name:     "LEEmail",
			Prompt:   &survey.Input{Message: "Lets Encrypt account email", Help: "Creates an account if it doesn't exist"},
			Validate: survey.Required,
		},
		{
			Name:   "AcmeRefresh",
			Prompt: &survey.Input{Message: "ACME API Refresh Token"},
		},
	}, &answers)
	if err != nil {
		fmt.Println("[Orchid] Error: ", err)
		return subcommands.ExitFailure
	}

	if answers.AcmeRefresh != "" {
		err = survey.Ask([]*survey.Question{
			{
				Name:     "AcmePresentUrl",
				Prompt:   &survey.Input{Message: "ACME API Present URL"},
				Validate: urlValidator,
			},
			{
				Name:     "AcmeCleanUpUrl",
				Prompt:   &survey.Input{Message: "ACME API Clean Up URL"},
				Validate: urlValidator,
			},
			{
				Name:     "AcmeRefreshUrl",
				Prompt:   &survey.Input{Message: "ACME API Refresh URL"},
				Validate: urlValidator,
			},
		}, &answers)
		if err != nil {
			fmt.Println("[Orchid] Error: ", err)
			return subcommands.ExitFailure
		}
	}

	key, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), 4096)
	if err != nil {
		fmt.Println("[Orchid] Error: ", err)
		return subcommands.ExitFailure
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyBuf := new(bytes.Buffer)
	err = pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		fmt.Println("[Orchid] Error: ", err)
		return subcommands.ExitFailure
	}

	// write config file
	confFile := filepath.Join(wdAbs, "config.yml")
	createConf, err := os.Create(confFile)
	if err != nil {
		fmt.Println("[Orchid] Failed to create config file: ", err)
		return subcommands.ExitFailure
	}

	confEncode := yaml.NewEncoder(createConf)
	confEncode.SetIndent(2)
	err = confEncode.Encode(startUpConfig{
		Listen: answers.ApiListen,
		Acme: acmeConfig{
			PresentUrl: answers.AcmePresentUrl,
			CleanUpUrl: answers.AcmeCleanUpUrl,
			RefreshUrl: answers.AcmeRefreshUrl,
		},
		LE: renewal.LetsEncryptConfig{
			Account: renewal.LetsEncryptAccount{
				Email:      answers.LEEmail,
				PrivateKey: keyBuf.String(),
			},
			Directory:   "production",
			Certificate: "default",
		},
		Domains: strings.Split(answers.ApiDomains, ","),
	})
	if err != nil {
		fmt.Println("[Orchid] Failed to write config file: ", err)
		return subcommands.ExitFailure
	}

	// write token file
	tokenFile := filepath.Join(wdAbs, "tokens.yml")
	createTokens, err := os.Create(tokenFile)
	if err != nil {
		fmt.Println("[Orchid] Failed to create tokens file: ", err)
		return subcommands.ExitFailure
	}

	confEncode = yaml.NewEncoder(createTokens)
	confEncode.SetIndent(2)
	err = confEncode.Encode(httpAcme.AcmeLogin{
		Access:  "",
		Refresh: answers.AcmeRefresh,
	})
	if err != nil {
		fmt.Println("[Orchid] Failed to write tokens file: ", err)
		return subcommands.ExitFailure
	}

	fmt.Println("[Orchid] Setup complete")
	fmt.Printf("[Orchid] Run the renewal service with `orchid serve -conf %s`\n", confFile)

	return subcommands.ExitSuccess
}

func listenAddressValidator(ans interface{}) error {
	if ansStr, ok := ans.(string); ok {
		// empty string means disable
		if ansStr == "" {
			return nil
		}

		// use ResolveTCPAddr to validate the input
		_, err := net.ResolveTCPAddr("tcp", ansStr)
		return err
	}
	return nil
}

func urlValidator(ans interface{}) error {
	if ansStr, ok := ans.(string); ok {
		_, err := url.Parse(ansStr)
		return err
	}
	return nil
}
