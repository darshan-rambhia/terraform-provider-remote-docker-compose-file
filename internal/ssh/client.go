package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/darshan-rambhia/gosftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// AuthMethod represents the SSH authentication method to use.
type AuthMethod string

const (
	// AuthMethodPrivateKey uses SSH private key authentication (default).
	AuthMethodPrivateKey AuthMethod = "private_key"
	// AuthMethodPassword uses password authentication.
	AuthMethodPassword AuthMethod = "password"
	// AuthMethodCertificate uses SSH certificate authentication.
	AuthMethodCertificate AuthMethod = "certificate"
)

// Config holds SSH connection configuration.
type Config struct {
	Host string
	Port int
	User string

	// Authentication method (defaults to private_key if not specified).
	AuthMethod AuthMethod

	// Private key authentication.
	PrivateKey string // Key content (PEM encoded)
	KeyPath    string // Path to key file

	// Password authentication.
	Password string

	// Certificate authentication.
	Certificate     string // Certificate content
	CertificatePath string // Path to certificate file

	// Connection options.
	Timeout time.Duration // Connection timeout (default 30s)

	// Host key verification.
	KnownHostsFile        string // Path to known_hosts file
	InsecureIgnoreHostKey bool   // Skip host key verification (DANGEROUS)

	// Bastion/Jump host configuration for multihop SSH.
	BastionHost     string
	BastionPort     int
	BastionUser     string
	BastionKey      string // Private key content for bastion
	BastionKeyPath  string // Path to private key for bastion
	BastionPassword string // Password for bastion (if using password auth)
}

// ClientInterface defines the interface for SSH/SFTP operations.
type ClientInterface interface {
	Close() error
	UploadFile(ctx context.Context, localPath, remotePath string) error
	UploadContent(ctx context.Context, content []byte, remotePath string) error
	GetFileHash(ctx context.Context, remotePath string) (string, error)
	SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error
	DeleteFile(ctx context.Context, remotePath string) error
	FileExists(ctx context.Context, remotePath string) (bool, error)
	GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error)
	ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error)
	RunCommand(ctx context.Context, command string) (stdout string, stderr string, err error)
}

// Client wraps gosftp and SSH connections for file operations.
type Client struct {
	gosftpClient *gosftp.Client
	sshClient    *ssh.Client
	config       Config
}

var _ ClientInterface = (*Client)(nil)

// NewClient creates a new SSH/SFTP client using gosftp.
func NewClient(config Config) (*Client, error) {
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
		BastionHost:           config.BastionHost,
		BastionPort:           config.BastionPort,
		BastionUser:           config.BastionUser,
		BastionKey:            config.BastionKey,
		BastionKeyPath:        config.BastionKeyPath,
		BastionPassword:       config.BastionPassword,
	}

	gosftpClient, err := gosftp.NewClient(gosftpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create gosftp client: %w", err)
	}

	// For RunCommand support, we need the underlying SSH client
	// We'll keep a separate SSH client for command execution
	var sshClient *ssh.Client

	return &Client{
		gosftpClient: gosftpClient,
		sshClient:    sshClient,
		config:       config,
	}, nil
}

func connectToBastion(config Config, timeout time.Duration) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if config.BastionPassword != "" {
		authMethods = append(authMethods, ssh.Password(config.BastionPassword))
	} else {
		var keyData []byte
		var err error

		if config.BastionKey != "" {
			keyData = []byte(config.BastionKey)
		} else if config.BastionKeyPath != "" {
			keyData, err = os.ReadFile(ExpandPath(config.BastionKeyPath))
			if err != nil {
				return nil, fmt.Errorf("failed to read bastion key file: %w", err)
			}
		} else {
			if config.PrivateKey != "" {
				keyData = []byte(config.PrivateKey)
			} else if config.KeyPath != "" {
				keyData, err = os.ReadFile(ExpandPath(config.KeyPath))
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

	hostKeyCallback, err := buildHostKeyCallback(config)
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
	return ssh.Dial("tcp", bastionAddr, bastionConfig)
}

func buildHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
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

	homeDir, err := os.UserHomeDir()
	if err == nil {
		defaultKnownHosts := filepath.Join(homeDir, ".ssh", "known_hosts")
		if _, err := os.Stat(defaultKnownHosts); err == nil {
			callback, err := knownhosts.New(defaultKnownHosts)
			if err == nil {
				return callback, nil
			}
		}
	}

	return nil, fmt.Errorf("no known_hosts file found and insecure_ignore_host_key is not set; either set insecure_ignore_host_key=true for development/testing or configure known_hosts_file")
}

// ExpandPath expands ~ to home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, path[2:])
		}
	}
	return path
}

var validOwnerGroupPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$|^[0-9]+$`)

func validateOwnerGroup(name, fieldName string) error {
	if name == "" {
		return nil
	}
	if len(name) > 32 {
		return fmt.Errorf("%s name too long (max 32 characters): %s", fieldName, name)
	}
	if !validOwnerGroupPattern.MatchString(name) {
		return fmt.Errorf("invalid %s name (must be alphanumeric, underscore, hyphen, or numeric): %s", fieldName, name)
	}
	return nil
}

// ShellQuote returns a shell-escaped version of the string.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

var validModePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

// ValidateMode checks if a file mode string is valid.
func ValidateMode(mode string) error {
	if mode == "" {
		return nil
	}
	if !validModePattern.MatchString(mode) {
		return fmt.Errorf("invalid mode %q: must be 3-4 octal digits (e.g., \"644\", \"0755\")", mode)
	}
	return nil
}

func buildAuthMethods(config Config) ([]ssh.AuthMethod, error) {
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
		certAuth, err := buildCertificateAuth(config)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication failed: %w", err)
		}
		authMethods = append(authMethods, certAuth)

	case AuthMethodPrivateKey, "":
		keyAuth, err := buildPrivateKeyAuth(config)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, keyAuth)
	}

	return authMethods, nil
}

func inferAuthMethod(config Config) AuthMethod {
	if config.Password != "" {
		return AuthMethodPassword
	}
	if config.Certificate != "" || config.CertificatePath != "" {
		return AuthMethodCertificate
	}
	return AuthMethodPrivateKey
}

func buildPrivateKeyAuth(config Config) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(ExpandPath(config.KeyPath))
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

func buildCertificateAuth(config Config) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(ExpandPath(config.KeyPath))
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
		certData, err = os.ReadFile(ExpandPath(config.CertificatePath))
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

// Close closes the gosftp client and SSH connections.
func (c *Client) Close() error {
	if c.gosftpClient != nil {
		return c.gosftpClient.Close()
	}
	return nil
}

// UploadFile uploads a local file to the remote host.
func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string) error {
	return c.gosftpClient.UploadFile(ctx, localPath, remotePath)
}

// UploadContent uploads content directly to the remote host.
// Since gosftp doesn't have a direct UploadContent method, we write to a temp file first.
func (c *Client) UploadContent(ctx context.Context, content []byte, remotePath string) error {
	// Write content to a temporary file
	tmpFile, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	tmpFile.Close()

	// Upload the temporary file
	return c.gosftpClient.UploadFile(ctx, tmpFile.Name(), remotePath)
}

// GetFileHash returns the SHA256 hash of a remote file.
func (c *Client) GetFileHash(ctx context.Context, remotePath string) (string, error) {
	return c.gosftpClient.GetFileHash(ctx, remotePath)
}

// SetFileAttributes sets ownership and permissions on a remote file.
func (c *Client) SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error {
	if err := validateOwnerGroup(owner, "owner"); err != nil {
		return err
	}
	if err := validateOwnerGroup(group, "group"); err != nil {
		return err
	}
	if err := ValidateMode(mode); err != nil {
		return err
	}

	return c.gosftpClient.SetFileAttributes(ctx, remotePath, owner, group, mode)
}

// DeleteFile removes a file from the remote host.
func (c *Client) DeleteFile(ctx context.Context, remotePath string) error {
	return c.gosftpClient.DeleteFile(ctx, remotePath)
}

// FileExists checks if a file exists on the remote host.
func (c *Client) FileExists(ctx context.Context, remotePath string) (bool, error) {
	return c.gosftpClient.FileExists(ctx, remotePath)
}

// GetFileInfo returns information about a remote file.
func (c *Client) GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error) {
	return c.gosftpClient.GetFileInfo(ctx, remotePath)
}

// ReadFileContent reads the content of a remote file.
func (c *Client) ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	return c.gosftpClient.ReadFileContent(ctx, remotePath, maxBytes)
}

// RunCommand executes a command on the remote host.
// Returns stdout, stderr, and any error.
func (c *Client) RunCommand(ctx context.Context, command string) (string, string, error) {
	// Check if context is already cancelled
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("context already cancelled: %w", err)
	}

	// For now, we need to create an SSH client for command execution
	// since gosftp focuses on SFTP operations
	authMethods, err := buildAuthMethods(c.config)
	if err != nil {
		return "", "", fmt.Errorf("failed to build auth methods: %w", err)
	}

	hostKeyCallback, err := buildHostKeyCallback(c.config)
	if err != nil {
		return "", "", fmt.Errorf("failed to build host key callback: %w", err)
	}

	timeout := c.config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// If context has a deadline, use the smaller of context deadline and configured timeout
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

	// Check context before establishing connections
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("context cancelled before connecting: %w", err)
	}

	var sshClient *ssh.Client
	var bastionClient *ssh.Client

	if c.config.BastionHost != "" {
		bastionClient, err = connectToBastion(c.config, timeout)
		if err != nil {
			return "", "", fmt.Errorf("failed to connect to bastion host: %w", err)
		}
		defer func() {
			if closeErr := bastionClient.Close(); closeErr != nil {
				// Log but don't fail - bastion close error shouldn't block command execution
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
		sshClient, err = ssh.Dial("tcp", targetAddr, sshConfig)
		if err != nil {
			return "", "", fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
		}
	}
	defer func() {
		if closeErr := sshClient.Close(); closeErr != nil {
			// Log but don't fail - close error shouldn't block command result
			_ = closeErr
		}
	}()

	session, err := sshClient.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			// Log but don't fail - close error shouldn't block command result
			_ = closeErr
		}
	}()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(command)
	return stdout.String(), stderr.String(), err
}

// IsBinaryContent checks if content appears to be binary.
func IsBinaryContent(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}
