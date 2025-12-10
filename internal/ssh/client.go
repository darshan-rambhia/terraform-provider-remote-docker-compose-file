package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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
	StrictHostKeyChecking string // "yes", "no", or "accept-new" (OpenSSH-style)

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

// GoSFTPClientInterface represents the interface for gosftp operations.
// This matches the gosftp.Client interface for testability.
type GoSFTPClientInterface interface {
	Close() error
	UploadFile(ctx context.Context, localPath, remotePath string) error
	GetFileHash(ctx context.Context, remotePath string) (string, error)
	SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error
	DeleteFile(ctx context.Context, remotePath string) error
	FileExists(ctx context.Context, remotePath string) (bool, error)
	GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error)
	ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error)
}

// Client wraps gosftp and SSH connections for file operations.
type Client struct {
	gosftpClient GoSFTPClientInterface
	sshClient    *ssh.Client
	config       Config
	deps         *Dependencies
}

var _ ClientInterface = (*Client)(nil)

// NewClient creates a new SSH/SFTP client using gosftp.
// Uses default production dependencies. For testing, use NewClientFactory.
func NewClient(config Config) (*Client, error) {
	return newClientWithDeps(config, DefaultDependencies())
}

func connectToBastion(config Config, timeout time.Duration) (*ssh.Client, error) {
	return connectToBastionWithDeps(config, timeout, DefaultDependencies())
}

func buildHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
	return buildHostKeyCallbackWithDeps(config, DefaultDependencies())
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
	return buildAuthMethodsWithDeps(config, DefaultDependencies())
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
	return buildPrivateKeyAuthWithDeps(config, DefaultDependencies())
}

func buildCertificateAuth(config Config) (ssh.AuthMethod, error) {
	return buildCertificateAuthWithDeps(config, DefaultDependencies())
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
	deps := c.deps
	if deps == nil {
		deps = DefaultDependencies()
	}
	return c.runCommandWithDeps(ctx, command, deps)
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
