package main

type startUpConfig struct {
	Database string `json:"db"`
	PrivKey  string `json:"priv_key"`
	PubKey   string `json:"pub_key"`
	Listen   string `json:"listen"`
}
