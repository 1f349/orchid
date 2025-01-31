package main

import (
	"encoding/pem"
	"github.com/1f349/orchid/logger"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
)

// loadAgentPrivateKey simply attempts to load the agent ssh private key and if
// it is missing generates a new key
func loadAgentPrivateKey(wd string) ssh.Signer {
	// load or create a key for orchid agent
	agentPrivKeyPath := filepath.Join(wd, "agent_id_ed25519")
	agentPubKeyPath := filepath.Join(wd, "agent_id_ed25519.pub")
	agentPrivKeyBytes, err := os.ReadFile(agentPrivKeyPath)
	switch {
	case err == nil:
		break
	case os.IsNotExist(err):
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			logger.Logger.Fatal("Failed to generate agent private key", "err", err)
		}
		marshalPrivKey, err := ssh.MarshalPrivateKey(privKey, "orchid-agent")
		if err != nil {
			logger.Logger.Fatal("Failed to encode private key", "err", err)
		}
		agentPrivKeyBytes = pem.EncodeToMemory(marshalPrivKey)

		// public key
		sshPubKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			logger.Logger.Fatal("Failed to encode public key", "err", err)
		}
		marshalPubKey := ssh.MarshalAuthorizedKey(sshPubKey)
		if err != nil {
			logger.Logger.Fatal("Failed to encode public key", "err", err)
		}

		// write to files
		err = os.WriteFile(agentPrivKeyPath, agentPrivKeyBytes, 0600)
		if err != nil {
			logger.Logger.Fatal("Failed to write agent private key", "path", agentPrivKeyPath, "err", err)
		}
		err = os.WriteFile(agentPubKeyPath, marshalPubKey, 0644)
		if err != nil {
			logger.Logger.Fatal("Failed to write agent public key", "path", agentPubKeyPath, "err", err)
		}

		// we can continue now
		break
	case err != nil:
		logger.Logger.Fatal("Failed to read agent private key", "path", agentPrivKeyPath, "err", err)
	}

	privKey, err := ssh.ParsePrivateKey(agentPrivKeyBytes)
	if err != nil {
		logger.Logger.Fatal("Failed to parse agent private key file", "path", agentPrivKeyPath, "err", err)
	}

	return privKey
}
