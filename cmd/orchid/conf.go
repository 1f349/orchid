package main

import "github.com/MrMelon54/orchid/renewal"

type startUpConfig struct {
	Database string                    `json:"db"`
	PrivKey  string                    `json:"priv_key"`
	PubKey   string                    `json:"pub_key"`
	Listen   string                    `json:"listen"`
	Acme     acmeConfig                `json:"acme"`
	LE       renewal.LetsEncryptConfig `json:"lets_encrypt"`
	Domains  []string                  `json:"domains"`
}

type acmeConfig struct {
	Access     string `json:"access"`
	Refresh    string `json:"refresh"`
	PresentUrl string `json:"present_url"`
	CleanUpUrl string `json:"clean_up_url"`
	RefreshUrl string `json:"refresh_url"`
}
