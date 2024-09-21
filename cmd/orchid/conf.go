package main

import (
	"github.com/1f349/orchid/renewal"
	"github.com/1f349/simplemail"
)

type startUpConfig struct {
	Listen  string                    `yaml:"listen"`
	Acme    acmeConfig                `yaml:"acme"`
	LE      renewal.LetsEncryptConfig `yaml:"letsEncrypt"`
	Domains []string                  `yaml:"domains"`
	Mail    mailConfig                `yaml:"mail"`
}

type acmeConfig struct {
	PresentUrl string `yaml:"presentUrl"`
	CleanUpUrl string `yaml:"cleanUpUrl"`
	RefreshUrl string `yaml:"refreshUrl"`
}

type mailConfig struct {
	simplemail.Mail
	To simplemail.FromAddress `yaml:"to"`
}
