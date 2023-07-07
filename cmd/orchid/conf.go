package main

import "github.com/MrMelon54/orchid/renewal"

type startUpConfig struct {
	Listen  string                    `yaml:"listen"`
	Acme    acmeConfig                `yaml:"acme"`
	LE      renewal.LetsEncryptConfig `yaml:"letsEncrypt"`
	Domains []string                  `yaml:"domains"`
}

type acmeConfig struct {
	PresentUrl string `yaml:"presentUrl"`
	CleanUpUrl string `yaml:"cleanUpUrl"`
	RefreshUrl string `yaml:"refreshUrl"`
}
