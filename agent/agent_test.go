package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/logger"
	"github.com/charmbracelet/log"
	"github.com/mrmelon54/certgen"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentSyncing(t *testing.T) {
	logger.Logger.SetLevel(log.DebugLevel)

	if testing.Short() {
		t.Skip("Skipping agent syncing tests in short mode")
	}

	t.Run("agent syncing test", func(t *testing.T) {
		certDir, err := os.MkdirTemp("", "orchid-certs")
		assert.NoError(t, err)
		keyDir, err := os.MkdirTemp("", "orchid-keys")
		assert.NoError(t, err)

		defer func() {
			assert.NoError(t, os.RemoveAll(certDir))
			assert.NoError(t, os.RemoveAll(keyDir))
		}()

		_, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		sshPrivKey, err := ssh.NewSignerFromKey(privKey)
		if err != nil {
			panic(err)
		}

		agent := &Agent{
			db:       &fakeAgentDb{},
			ticker:   nil,
			done:     nil,
			syncLock: nil,
			sshKey:   sshPrivKey,
			certDir:  certDir,
			keyDir:   keyDir,
		}

		now := time.Now().UTC()

		t.Run("missing cert file", func(t *testing.T) {
			err = agent.syncSingleAgentCertPair(now, database.FindAgentToSyncRow{
				AgentID:      1337,
				Address:      "",
				User:         "test",
				Dir:          "~/hello/world",
				Fingerprint:  "",
				CertID:       420,
				CertNotAfter: sql.NullTime{Time: now, Valid: true},
			})
			assert.Contains(t, err.Error(), "open cert file:")
			assert.Contains(t, err.Error(), "no such file or directory")
		})

		// generate example certificate
		tlsCert, err := certgen.MakeServerTls(nil, 2048, pkix.Name{
			Country:       []string{"GB"},
			Province:      []string{"London"},
			StreetAddress: []string{"221B Baker Street"},
			PostalCode:    []string{"NW1 6XE"},
			SerialNumber:  "test123456",
			CommonName:    "orchid-agent-test.local",
		}, big.NewInt(1234567899), func(now time.Time) time.Time {
			return now.Add(1 * time.Hour)
		}, []string{"orchid-agent-test.local"}, []net.IP{
			net.IPv6loopback,
			net.IPv4(127, 0, 0, 1),
		})
		assert.NoError(t, err)

		err = os.WriteFile(filepath.Join(certDir, "420.cert.pem"), tlsCert.GetCertPem(), 0600)
		assert.NoError(t, err)

		t.Run("missing key file", func(t *testing.T) {
			err = agent.syncSingleAgentCertPair(now, database.FindAgentToSyncRow{
				AgentID:      1337,
				Address:      "",
				User:         "test",
				Dir:          "~/hello/world",
				Fingerprint:  "",
				CertID:       420,
				CertNotAfter: sql.NullTime{Time: now, Valid: true},
			})
			assert.Contains(t, err.Error(), "open key file:")
			assert.Contains(t, err.Error(), "no such file or directory")
		})

		err = os.WriteFile(filepath.Join(keyDir, "420.key.pem"), tlsCert.GetKeyPem(), 0600)
		assert.NoError(t, err)

		t.Run("successful sync", func(t *testing.T) {
			var wg sync.WaitGroup
			server := setupFakeSSH(&wg, func(remoteAddrPort netip.AddrPort, remotePubKey ssh.PublicKey) {
				println("Attempt agent syncing")

				err = agent.syncSingleAgentCertPair(now, database.FindAgentToSyncRow{
					AgentID:      1337,
					Address:      remoteAddrPort.String(),
					User:         "test",
					Dir:          "~/hello/world",
					Fingerprint:  string(ssh.MarshalAuthorizedKey(remotePubKey)),
					CertID:       420,
					CertNotAfter: sql.NullTime{Time: now, Valid: true},
				})
				assert.NoError(t, err)
			})
			server.Close()

			println("Waiting for ssh server to exit")

			server.Wait()
		})
	})
}

func setupFakeSSH(wg *sync.WaitGroup, call func(addrPort netip.AddrPort, pubKey ssh.PublicKey)) *ssh.ServerConn {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		panic(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		panic(err)
	}

	tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		panic(err)
	}

	addrPort := tcp.Addr().(*net.TCPAddr).AddrPort()

	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		call(addrPort, sshPubKey)
	}()

	tcpConn, err := tcp.AcceptTCP()
	if err != nil {
		panic(err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() != "test" {
				return nil, fmt.Errorf("invalid user")
			}
			if !conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().IsLoopback() {
				return nil, fmt.Errorf("invalid remote address")
			}
			return &ssh.Permissions{}, nil
		},
		ServerVersion: "SSH-2.0-OrchidTester",
	}
	serverConfig.AddHostKey(sshSigner)

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, serverConfig)
	if err != nil {
		panic(err)
	}

	// The incoming Request channel must be serviced.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Service the incoming channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of a shell, the type is
			// "session" and ServerShell may be used to present a simple
			// terminal interface.
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				panic(err)
			}

			var fullFilePath string

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "shell" request.
			wg.Add(1)
			go func(in <-chan *ssh.Request) {
				for req := range in {
					req.Reply(req.Type == "exec", nil)
					if req.Type == "exec" {
						length := binary.BigEndian.Uint32(req.Payload[:4])
						if len(req.Payload) != int(length)+4 {
							panic(fmt.Errorf("invalid exec payload (expected %d but got %d)", length, len(req.Payload)))
						}
						cmd := string(req.Payload[4:])
						const scpStartStr = "scp -qt \""
						if !strings.HasPrefix(cmd, scpStartStr) {
							panic("invalid start")
						}
						if !strings.HasSuffix(cmd, "\"") {
							panic("invalid end")
						}
						filePath := cmd[len(scpStartStr) : len(cmd)-1]
						fmt.Println("Writing file:", filePath)
						fullFilePath = filePath
					}
				}
				wg.Done()
			}(requests)

			wg.Add(1)
			go func() {
				defer func() {
					channel.Close()
					wg.Done()
				}()

				var b [1024]byte
				read := must(channel.Read(b[:]))
				if read < 1 {
					panic("invalid read")
				}

				fmt.Println(string(b[:read]))

				r := bufio.NewReader(bytes.NewReader(b[:read]))
				if readByte(r) != 'C' {
					panic("invalid scp command")
				}

				fileMode := readN(r, 4)
				if string(fileMode) != "0600" {
					panic("unexpected file mode")
				}

				if readByte(r) != ' ' {
					panic("missing space")
				}

				fileSizeStr := must(r.ReadString(' '))
				fileSize := must(strconv.Atoi(fileSizeStr[:len(fileSizeStr)-1]))

				fileName := strings.TrimSpace(string(must(io.ReadAll(r))))
				if fileName != filepath.Base(fullFilePath) {
					panic(fmt.Errorf("invalid file name (expected \"%s\" from full path \"%s\" but got \"%s\")", filepath.Base(fullFilePath), fullFilePath, fileName))
				}

				if fileName != "420.cert.pem" && fileName != "420.key.pem" {
					panic("invalid file name")
				}

				channel.Write([]byte{0})

				buf := new(bytes.Buffer)
				_, err := io.CopyN(buf, channel, int64(fileSize))
				if err != nil {
					panic("Failed to copy channel")
				}
				fmt.Println("Copied file with size:", buf.Len())
				fmt.Println(buf.String())

				if readLastByte(r) != 0x00 {
					panic("expected ending null byte")
				}

				channel.Write([]byte{0})

				channel.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
			}()
		}
	}()

	wg2.Wait()

	return sshConn
}

type fakeAgentDb struct{}

func (f *fakeAgentDb) FindAgentToSync(ctx context.Context) ([]database.FindAgentToSyncRow, error) {
	panic("implement me")
}

func (f *fakeAgentDb) UpdateAgentLastSync(ctx context.Context, arg database.UpdateAgentLastSyncParams) error {
	if arg.ID != 1337 {
		return fmt.Errorf("invalid agent id")
	}
	if !arg.LastSync.Valid {
		return fmt.Errorf("invalid last sync")
	}
	return nil
}

func (f *fakeAgentDb) UpdateAgentCertNotAfter(ctx context.Context, arg database.UpdateAgentCertNotAfterParams) error {
	if arg.AgentID != 1337 {
		return fmt.Errorf("invalid agent id")
	}
	if arg.CertID != 420 {
		return fmt.Errorf("invalid cert id")
	}
	if !arg.NotAfter.Valid {
		return fmt.Errorf("invalid not after")
	}
	return nil
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func readN(r io.Reader, n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	if err != nil {
		panic(err)
	}
	return b
}

func readByte(r io.Reader) byte {
	b := readN(r, 1)
	return b[0]
}

func readLastByte(r io.Reader) byte {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	if !errors.Is(err, io.EOF) {
		panic("expected EOF")
	}
	return b[0]
}
