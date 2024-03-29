package sshtun

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/user"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var defaultSSHKeys = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"}

// AuthType is the type of authentication to use for SSH.
type AuthType int

const (
	// AuthTypeKeyFile uses the keys from a SSH key file read from the system.
	AuthTypeKeyFile AuthType = iota
	// AuthTypeEncryptedKeyFile uses the keys from an encrypted SSH key file read from the system.
	AuthTypeEncryptedKeyFile
	// AuthTypeKeyReader uses the keys from a SSH key reader.
	AuthTypeKeyReader
	// AuthTypeEncryptedKeyReader uses the keys from an encrypted SSH key reader.
	AuthTypeEncryptedKeyReader
	// AuthTypePassword uses a password directly.
	AuthTypePassword
	// AuthTypeSSHAgent will use registered users in the ssh-agent.
	AuthTypeSSHAgent
	// AuthTypeAuto tries to get the authentication method automatically. See SSHTun.Start for details on
	// this.
	AuthTypeAuto
)

func (tun *SSHTun) getSSHAuthMethod() (ssh.AuthMethod, error) {
	switch tun.authType {
	case AuthTypeKeyFile:
		return tun.getSSHAuthMethodForKeyFile(false)
	case AuthTypeEncryptedKeyFile:
		return tun.getSSHAuthMethodForKeyFile(true)
	case AuthTypeKeyReader:
		return tun.getSSHAuthMethodForKeyReader(false)
	case AuthTypeEncryptedKeyReader:
		return tun.getSSHAuthMethodForKeyReader(true)
	case AuthTypePassword:
		return ssh.Password(tun.authPassword), nil
	case AuthTypeSSHAgent:
		return tun.getSSHAuthMethodForSSHAgent()
	case AuthTypeAuto:
		method, errFile := tun.getSSHAuthMethodForKeyFile(false)
		if errFile == nil {
			return method, nil
		}
		method, errAgent := tun.getSSHAuthMethodForSSHAgent()
		if errAgent == nil {
			return method, nil
		}
		return nil, fmt.Errorf("auto auth failed (file based: %v) (ssh-agent: %v)", errFile, errAgent)
	default:
		return nil, fmt.Errorf("unknown auth type: %d", tun.authType)
	}
}

func (tun *SSHTun) getSSHAuthMethodForKeyFile(encrypted bool) (ssh.AuthMethod, error) {
	if tun.authKeyFile != "" {
		return tun.readPrivateKey(tun.authKeyFile, encrypted)
	}

	homeDir := "/root"
	usr, _ := user.Current()
	if usr != nil {
		homeDir = usr.HomeDir
	}

	for _, keyName := range defaultSSHKeys {
		keyFile := fmt.Sprintf("%s/.ssh/%s", homeDir, keyName)
		authMethod, err := tun.readPrivateKey(keyFile, encrypted)
		if err == nil {
			return authMethod, nil
		}
	}

	return nil, fmt.Errorf("could not read any default SSH key (%v)", defaultSSHKeys)
}

func (tun *SSHTun) readPrivateKey(keyFile string, encrypted bool) (ssh.AuthMethod, error) {
	buf, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key file %s: %w", keyFile, err)
	}

	key, err := tun.parsePrivateKey(buf, encrypted)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key file %s: %w", keyFile, err)
	}

	return key, nil
}

func (tun *SSHTun) getSSHAuthMethodForKeyReader(encrypted bool) (ssh.AuthMethod, error) {
	buf, err := io.ReadAll(tun.authKeyReader)
	if err != nil {
		return nil, fmt.Errorf("reading from SSH key reader: %w", err)
	}
	key, err := tun.parsePrivateKey(buf, encrypted)
	if err != nil {
		return nil, fmt.Errorf("reading from SSH key reader: %w", err)
	}
	return key, nil
}

func (tun *SSHTun) parsePrivateKey(buf []byte, encrypted bool) (ssh.AuthMethod, error) {
	var key ssh.Signer
	var err error
	if encrypted {
		key, err = ssh.ParsePrivateKeyWithPassphrase(buf, []byte(tun.authPassword))
		if err != nil {
			return nil, fmt.Errorf("parsing encrypted key: %w", err)
		}
	} else {
		key, err = ssh.ParsePrivateKey(buf)
		if err != nil {
			return nil, fmt.Errorf("error parsing key: %w", err)
		}
	}
	return ssh.PublicKeys(key), nil
}

func (tun *SSHTun) getSSHAuthMethodForSSHAgent() (ssh.AuthMethod, error) {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("opening unix socket: %w", err)
	}

	agentClient := agent.NewClient(conn)

	signers, err := agentClient.Signers()
	if err != nil {
		return nil, fmt.Errorf("getting ssh-agent signers: %w", err)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no signers from ssh-agent (use 'ssh-add' to add keys to agent)")
	}

	return ssh.PublicKeys(signers...), nil
}
