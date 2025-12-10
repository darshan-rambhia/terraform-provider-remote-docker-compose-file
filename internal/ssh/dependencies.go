package ssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/darshan-rambhia/gosftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Dependencies holds all injectable dependencies for the SSH client.
// This enables testing by allowing mock implementations to be injected.
type Dependencies struct {
	// GoSFTPClientFactory creates a new gosftp client.
	GoSFTPClientFactory func(config gosftp.Config) (GoSFTPClientInterface, error)

	// SSHDialer dials an SSH connection.
	SSHDialer func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error)

	// FileReader reads a file from the filesystem.
	FileReader func(path string) ([]byte, error)

	// TempFileCreator creates a temporary file.
	TempFileCreator func(dir, pattern string) (*os.File, error)

	// HomeDir returns the user's home directory.
	HomeDir func() (string, error)

	// FileStat returns file info for a path.
	FileStat func(path string) (os.FileInfo, error)
}

// DefaultDependencies returns the default production dependencies.
func DefaultDependencies() *Dependencies {
	return &Dependencies{
		GoSFTPClientFactory: func(config gosftp.Config) (GoSFTPClientInterface, error) {
			return gosftp.NewClient(config)
		},
		SSHDialer:       ssh.Dial,
		FileReader:      os.ReadFile,
		TempFileCreator: os.CreateTemp,
		HomeDir:         os.UserHomeDir,
		FileStat:        os.Stat,
	}
}

// SSHClientWrapper wraps an ssh.Client to provide additional functionality.
type SSHClientWrapper interface {
	Close() error
	Dial(network, addr string) (net.Conn, error)
	NewSession() (*ssh.Session, error)
}

// realSSHClient wraps a real ssh.Client.
type realSSHClient struct {
	client *ssh.Client
}

func (r *realSSHClient) Close() error {
	return r.client.Close()
}

func (r *realSSHClient) Dial(network, addr string) (net.Conn, error) {
	return r.client.Dial(network, addr)
}

func (r *realSSHClient) NewSession() (*ssh.Session, error) {
	return r.client.NewSession()
}

// WrapSSHClient wraps an ssh.Client in an SSHClientWrapper.
func WrapSSHClient(client *ssh.Client) SSHClientWrapper {
	return &realSSHClient{client: client}
}

// ClientFactory creates SSH clients with injectable dependencies.
type ClientFactory struct {
	deps *Dependencies
}

// NewClientFactory creates a new ClientFactory with the given dependencies.
// If deps is nil, default production dependencies are used.
func NewClientFactory(deps *Dependencies) *ClientFactory {
	if deps == nil {
		deps = DefaultDependencies()
	}
	return &ClientFactory{deps: deps}
}

// NewClient creates a new SSH/SFTP client using the factory's dependencies.
func (f *ClientFactory) NewClient(config Config) (*Client, error) {
	return newClientWithDeps(config, f.deps)
}

// newClientWithDeps creates a new client with the given dependencies.
func newClientWithDeps(config Config, deps *Dependencies) (*Client, error) {
	gosftpConfig := gosftp.Config{
		Host:                  config.Host,
		Port:                  config.Port,
		User:                  config.User,
		AuthMethod:            gosftp.AuthMethod(config.AuthMethod),
		PrivateKey:            config.PrivateKey,
		KeyPath:               config.KeyPath,
		Password:              config.Password,
		Certificate:           config.Certificate,
		CertificatePath:       config.CertificatePath,
		Timeout:               config.Timeout,
		KnownHostsFile:        config.KnownHostsFile,
		InsecureIgnoreHostKey: config.InsecureIgnoreHostKey,
		StrictHostKeyChecking: gosftp.StrictHostKeyChecking(config.StrictHostKeyChecking),
		BastionHost:           config.BastionHost,
		BastionPort:           config.BastionPort,
		BastionUser:           config.BastionUser,
		BastionKey:            config.BastionKey,
		BastionKeyPath:        config.BastionKeyPath,
		BastionPassword:       config.BastionPassword,
	}

	gosftpClient, err := deps.GoSFTPClientFactory(gosftpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create gosftp client: %w", err)
	}

	return &Client{
		gosftpClient: gosftpClient,
		sshClient:    nil,
		config:       config,
		deps:         deps,
	}, nil
}

// connectToBastionWithDeps connects to a bastion host using the given dependencies.
func connectToBastionWithDeps(config Config, timeout time.Duration, deps *Dependencies) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if config.BastionPassword != "" {
		authMethods = append(authMethods, ssh.Password(config.BastionPassword))
	} else {
		var keyData []byte
		var err error

		if config.BastionKey != "" {
			keyData = []byte(config.BastionKey)
		} else if config.BastionKeyPath != "" {
			keyData, err = deps.FileReader(ExpandPath(config.BastionKeyPath))
			if err != nil {
				return nil, fmt.Errorf("failed to read bastion key file: %w", err)
			}
		} else {
			if config.PrivateKey != "" {
				keyData = []byte(config.PrivateKey)
			} else if config.KeyPath != "" {
				keyData, err = deps.FileReader(ExpandPath(config.KeyPath))
				if err != nil {
					return nil, fmt.Errorf("failed to read key file for bastion: %w", err)
				}
			} else {
				return nil, fmt.Errorf("no SSH key configured for bastion host")
			}
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bastion SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	bastionUser := config.BastionUser
	if bastionUser == "" {
		bastionUser = config.User
	}

	bastionPort := config.BastionPort
	if bastionPort == 0 {
		bastionPort = 22
	}

	hostKeyCallback, err := buildHostKeyCallbackWithDeps(config, deps)
	if err != nil {
		return nil, fmt.Errorf("failed to configure host key verification for bastion: %w", err)
	}

	bastionConfig := &ssh.ClientConfig{
		User:            bastionUser,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	bastionAddr := fmt.Sprintf("%s:%d", config.BastionHost, bastionPort)
	return deps.SSHDialer("tcp", bastionAddr, bastionConfig)
}

// buildHostKeyCallbackWithDeps builds a host key callback using the given dependencies.
func buildHostKeyCallbackWithDeps(config Config, deps *Dependencies) (ssh.HostKeyCallback, error) {
	if config.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if config.KnownHostsFile != "" {
		expandedPath := ExpandPath(config.KnownHostsFile)
		callback, err := knownhosts.New(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %s: %w", expandedPath, err)
		}
		return callback, nil
	}

	homeDir, err := deps.HomeDir()
	if err == nil {
		defaultKnownHosts := filepath.Join(homeDir, ".ssh", "known_hosts")
		if _, err := deps.FileStat(defaultKnownHosts); err == nil {
			callback, err := knownhosts.New(defaultKnownHosts)
			if err == nil {
				return callback, nil
			}
		}
	}

	return nil, fmt.Errorf("no known_hosts file found and insecure_ignore_host_key is not set; either set insecure_ignore_host_key=true for development/testing or configure known_hosts_file")
}

// buildAuthMethodsWithDeps builds auth methods using the given dependencies.
func buildAuthMethodsWithDeps(config Config, deps *Dependencies) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	authMethod := config.AuthMethod
	if authMethod == "" {
		authMethod = inferAuthMethod(config)
	}

	switch authMethod {
	case AuthMethodPassword:
		if config.Password == "" {
			return nil, fmt.Errorf("password authentication requires password to be set")
		}
		authMethods = append(authMethods, ssh.Password(config.Password))

	case AuthMethodCertificate:
		certAuth, err := buildCertificateAuthWithDeps(config, deps)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication failed: %w", err)
		}
		authMethods = append(authMethods, certAuth)

	case AuthMethodPrivateKey, "":
		keyAuth, err := buildPrivateKeyAuthWithDeps(config, deps)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, keyAuth)
	}

	return authMethods, nil
}

// buildPrivateKeyAuthWithDeps builds private key auth using the given dependencies.
func buildPrivateKeyAuthWithDeps(config Config, deps *Dependencies) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = deps.FileReader(ExpandPath(config.KeyPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no SSH private key provided (set private_key or key_path)")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// buildCertificateAuthWithDeps builds certificate auth using the given dependencies.
func buildCertificateAuthWithDeps(config Config, deps *Dependencies) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = deps.FileReader(ExpandPath(config.KeyPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires private key (set private_key or key_path)")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var certData []byte
	if config.Certificate != "" {
		certData = []byte(config.Certificate)
	} else if config.CertificatePath != "" {
		certData, err = deps.FileReader(ExpandPath(config.CertificatePath))
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires certificate (set certificate or certificate_path)")
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("provided file is not an SSH certificate")
	}

	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %w", err)
	}

	return ssh.PublicKeys(certSigner), nil
}

// runCommandWithDeps executes a command using the given dependencies.
func (c *Client) runCommandWithDeps(ctx context.Context, command string, deps *Dependencies) (string, string, error) {
	// Check if context is already cancelled
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("context already cancelled: %w", err)
	}

	authMethods, err := buildAuthMethodsWithDeps(c.config, deps)
	if err != nil {
		return "", "", fmt.Errorf("failed to build auth methods: %w", err)
	}

	hostKeyCallback, err := buildHostKeyCallbackWithDeps(c.config, deps)
	if err != nil {
		return "", "", fmt.Errorf("failed to build host key callback: %w", err)
	}

	timeout := c.config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	if deadline, ok := ctx.Deadline(); ok {
		timeUntilDeadline := time.Until(deadline)
		if timeUntilDeadline > 0 && timeUntilDeadline < timeout {
			timeout = timeUntilDeadline
		}
	}

	port := c.config.Port
	if port == 0 {
		port = 22
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	targetAddr := fmt.Sprintf("%s:%d", c.config.Host, port)

	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("context cancelled before connecting: %w", err)
	}

	var sshClient *ssh.Client
	var bastionClient *ssh.Client

	if c.config.BastionHost != "" {
		bastionClient, err = connectToBastionWithDeps(c.config, timeout, deps)
		if err != nil {
			return "", "", fmt.Errorf("failed to connect to bastion host: %w", err)
		}
		defer func() {
			if closeErr := bastionClient.Close(); closeErr != nil {
				_ = closeErr
			}
		}()

		conn, err := bastionClient.Dial("tcp", targetAddr)
		if err != nil {
			return "", "", fmt.Errorf("failed to dial target through bastion: %w", err)
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
		if err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				_ = closeErr
			}
			return "", "", fmt.Errorf("failed to create SSH connection through bastion: %w", err)
		}

		sshClient = ssh.NewClient(ncc, chans, reqs)
	} else {
		sshClient, err = deps.SSHDialer("tcp", targetAddr, sshConfig)
		if err != nil {
			return "", "", fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
		}
	}
	defer func() {
		if closeErr := sshClient.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	session, err := sshClient.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(command)
	return stdout.String(), stderr.String(), err
}
