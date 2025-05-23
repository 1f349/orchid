package main

import "github.com/1f349/orchid/renewal"

type startUpConfig struct {
	Listen   string                    `yaml:"listen"`
	Acme     acmeConfig                `yaml:"acme"`
	LE       renewal.LetsEncryptConfig `yaml:"letsEncrypt"`
	Domains  []string                  `yaml:"domains"`
	AgentKey string                    `yaml:"agentKey"`
}

type acmeConfig struct {
	PresentUrl string `yaml:"presentUrl"`
	CleanUpUrl string `yaml:"cleanUpUrl"`
	RefreshUrl string `yaml:"refreshUrl"`
}
