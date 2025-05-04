package agent

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/utils"
	"github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"sync"
	"time"
)

//go:embed agent_readme.md
var agentReadme []byte

type agentQueries interface {
	FindAgentToSync(ctx context.Context) ([]database.FindAgentToSyncRow, error)
	UpdateAgentLastSync(ctx context.Context, row database.UpdateAgentLastSyncParams) error
	UpdateAgentCertNotAfter(ctx context.Context, arg database.UpdateAgentCertNotAfterParams) error
}

func NewAgent(wg *sync.WaitGroup, db agentQueries, sshKey ssh.Signer, certDir string, keyDir string) (*Agent, error) {
	a := &Agent{
		db:       db,
		ticker:   time.NewTicker(time.Minute * 10),
		done:     make(chan struct{}),
		syncLock: new(sync.Mutex),
		sshKey:   sshKey,
		certDir:  certDir,
		keyDir:   keyDir,
	}

	wg.Add(1)
	go a.syncRoutine(wg)
	return a, nil
}

type Agent struct {
	db       agentQueries
	ticker   *time.Ticker
	done     chan struct{}
	syncLock *sync.Mutex
	sshKey   ssh.Signer
	certDir  string
	keyDir   string
}

func (a *Agent) Shutdown() {
	Logger.Info("Shutting down agent syncing service")
	close(a.done)
}

func (a *Agent) syncRoutine(wg *sync.WaitGroup) {
	Logger.Debug("Starting syncRoutine")

	// Upon leaving the function stop the ticker and clear the WaitGroup.
	defer func() {
		a.ticker.Stop()
		Logger.Info("Stopped agent syncing service")
		wg.Done()
	}()

	Logger.Info("Doing quick agent check before starting...")
	a.syncCheck()

	// Logging or something
	Logger.Info("Initial check complete, continually checking every 10 minutes...")

	// Main loop
	for {
		select {
		case <-a.done:
			// Exit if done has closed
			return
		case <-a.ticker.C:
			Logger.Debug("Ticking agent syncing")

			go a.syncCheck()
		}
	}
}

func (a *Agent) syncCheck() {
	// if the lock is unavailable then ignore this cycle
	if !a.syncLock.TryLock() {
		return
	}
	defer a.syncLock.Unlock()

	now := time.Now().UTC()

	actions, err := a.db.FindAgentToSync(context.Background())
	if err != nil {
		panic(err)
	}

	a.syncCertPairs(now, actions)
}

type syncAgent struct {
	agentId     int64
	address     string
	user        string
	fingerprint string
}

func (a *Agent) syncCertPairs(startTime time.Time, rows []database.FindAgentToSyncRow) {
	agentMap := make(map[syncAgent][]database.FindAgentToSyncRow)

	for _, row := range rows {
		a := syncAgent{
			agentId:     row.AgentID,
			address:     row.Address,
			user:        row.User,
			fingerprint: row.Fingerprint,
		}
		agentMap[a] = append(agentMap[a], row)
	}

	for agent, certPairs := range agentMap {
		err := a.syncSingleAgentCertPairs(startTime, agent, certPairs)
		if err != nil {
			// This agent sync is allowed to fail without stopping other agent syncs from
			// occurring.
			Logger.Warn("Agent sync failed", "agent", agent.agentId, "err", err)
		}
	}
}

func (a *Agent) syncSingleAgentCertPairs(startTime time.Time, agent syncAgent, rows []database.FindAgentToSyncRow) error {
	Logger.Debug("Syncing agent", "id", agent.agentId, "address", agent.address, "fingerprint", agent.fingerprint, "cert_count", len(rows))
	defer Logger.Debug("Finished syncing agent", "id", agent.agentId)

	hostPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(agent.fingerprint))
	if err != nil {
		return fmt.Errorf("failed to parse fingerprint: %w", err)
	}

	client, err := ssh.Dial("tcp", agent.address, &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{"curve25519-sha256"},
		},
		User: agent.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(a.sshKey),
		},
		HostKeyAlgorithms: []string{"ssh-ed25519"},
		HostKeyCallback:   ssh.FixedHostKey(hostPubKey),
		Timeout:           time.Second * 30,
	})
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}

	scpClient, err := scp.NewClientBySSH(client)
	if err != nil {
		return fmt.Errorf("scp client: %w", err)
	}

	hadError := false

	for _, row := range rows {
		Logger.Debug("Syncing certificate to agent", "id", agent.agentId, "address", agent.address, "fingerprint", agent.fingerprint, "cert_id", row.CertID, "not_after", row.CertNotAfter)

		err := a.copySingleCertPair(&scpClient, row)
		if err != nil {
			// This cert sync is allowed to fail without stopping other certs going to the
			// same agent from copying.
			err = fmt.Errorf("copySingleCertPair: %w", err)
			Logger.Warn("Agent certificate sync failed", "agent", row.AgentID, "cert", row.CertID, "not after", row.CertNotAfter, "err", err)
			hadError = true
			continue
		}
	}

	// The agent last sync will only update if all scp copies were successful.
	if !hadError {
		// Update last sync to the time when the database request happened. This ensures
		// that certificates updated after the database request and before the agent
		// syncing are updated properly.
		err = a.db.UpdateAgentLastSync(context.Background(), database.UpdateAgentLastSyncParams{
			LastSync: sql.NullTime{Time: startTime, Valid: true},
			ID:       agent.agentId,
		})
		if err != nil {
			return fmt.Errorf("error updating agent last sync: %v", err)
		}

		Logger.Debug("Successfully synced all agent certificates", "id", agent.agentId, "address", agent.address, "fingerprint", agent.fingerprint)
	}

	return nil
}

func (a *Agent) copySingleCertPair(scpClient *scp.Client, row database.FindAgentToSyncRow) error {
	certName := utils.GetCertFileName(row.CertID)
	keyName := utils.GetKeyFileName(row.CertID)

	certPath := filepath.Join(a.certDir, certName)
	keyPath := filepath.Join(a.keyDir, keyName)

	// open cert and key files
	openCert, err := os.Open(certPath)
	if err != nil {
		return fmt.Errorf("open cert file: %w", err)
	}
	defer openCert.Close()

	openKey, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	defer openKey.Close()

	// copy cert and key to agent
	err = scpClient.CopyFromFile(context.Background(), *openCert, filepath.Join(row.Dir, "certificates", certName), "0600")
	if err != nil {
		return fmt.Errorf("copy cert file: %w", err)
	}
	err = scpClient.CopyFromFile(context.Background(), *openKey, filepath.Join(row.Dir, "keys", keyName), "0600")
	if err != nil {
		return fmt.Errorf("copy cert file: %w", err)
	}

	err = a.db.UpdateAgentCertNotAfter(context.Background(), database.UpdateAgentCertNotAfterParams{
		NotAfter: row.CertNotAfter,
		AgentID:  row.AgentID,
		CertID:   row.CertID,
	})
	if err != nil {
		return fmt.Errorf("error updating agent last sync: %v", err)
	}

	return nil
}
