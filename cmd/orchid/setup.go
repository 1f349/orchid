package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	httpAcme "github.com/1f349/orchid/http-acme"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/renewal"
	"github.com/AlecAivazis/survey/v2"
	"gopkg.in/yaml.v3"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errExitSetup = errors.New("exit setup")

func runSetup(wd string) error {
	// ask about running the setup steps
	createFile := false
	err := survey.AskOne(&survey.Confirm{Message: fmt.Sprintf("Create Orchid config files in this directory: '%s'?", wd)}, &createFile)
	if err != nil {
		return err
	}
	if !createFile {
		logger.Logger.Info("Goodbye")
		return errExitSetup
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
		return err
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
			return err
		}
	}

	key, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), 4096)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyBuf := new(bytes.Buffer)
	err = pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return fmt.Errorf("failed to PEM encode private key: %w", err)
	}

	// write config file
	confFile := filepath.Join(wd, "config.yml")
	createConf, err := os.Create(confFile)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer createConf.Close()

	// this is the whole config structure
	config := startUpConfig{
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
	}

	confEncode := yaml.NewEncoder(createConf)
	confEncode.SetIndent(2)
	err = confEncode.Encode(config)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// write token file
	tokenFile := filepath.Join(wd, "tokens.yml")
	createTokens, err := os.Create(tokenFile)
	if err != nil {
		return fmt.Errorf("failed to create tokens file: %w", err)
	}

	confEncode = yaml.NewEncoder(createTokens)
	confEncode.SetIndent(2)
	err = confEncode.Encode(httpAcme.AcmeLogin{
		Access:  "",
		Refresh: answers.AcmeRefresh,
	})
	if err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}

	logger.Logger.Info("Setup complete")
	logger.Logger.Infof("Run the renewal service with `orchid-daemon -conf %s`", confFile)

	return nil
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
