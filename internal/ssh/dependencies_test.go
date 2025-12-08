package ssh

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/darshan-rambhia/gosftp"
	"golang.org/x/crypto/ssh"
)

// Test ED25519 private key for testing purposes (DO NOT use in production).
const testPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEouqaxbUUzB5Lmi89KTTnLNl1cS8Qos3pgTAE61GxpwAAAJAk7O6zJOzu
swAAAAtzc2gtZWQyNTUxOQAAACBEouqaxbUUzB5Lmi89KTTnLNl1cS8Qos3pgTAE61Gxpw
AAAEDJWGbpTx6RYfoGk2v/igTCJ6bzaQB7+EmeTO66dITu+kSi6prFtRTMHkuaLz0pNOcs
2XVxLxCizemBMATrUbGnAAAADXRlc3RAdGVzdC5jb20=
-----END OPENSSH PRIVATE KEY-----`

// TestNewClientWithDeps tests client creation with dependency injection.
func TestNewClientWithDeps_Success(t *testing.T) {
	mockGosftp := &MockGoSFTPClient{}

	deps := &Dependencies{
		GoSFTPClientFactory: func(config gosftp.Config) (GoSFTPClientInterface, error) {
			// Verify config is passed correctly
			if config.Host != "test.example.com" {
				t.Errorf("Expected host test.example.com, got %s", config.Host)
			}
			if config.Port != 2222 {
				t.Errorf("Expected port 2222, got %d", config.Port)
			}
			if config.User != "testuser" {
				t.Errorf("Expected user testuser, got %s", config.User)
			}
			return mockGosftp, nil
		},
	}

	config := Config{
		Host:                  "test.example.com",
		Port:                  2222,
		User:                  "testuser",
		Password:              "testpass",
		InsecureIgnoreHostKey: true,
	}

	client, err := newClientWithDeps(config, deps)
	if err != nil {
		t.Fatalf("newClientWithDeps() error = %v, want nil", err)
	}

	if client == nil {
		t.Fatal("newClientWithDeps() returned nil client")
	}

	if client.gosftpClient != mockGosftp {
		t.Error("newClientWithDeps() didn't use the injected gosftp client")
	}

	if client.deps != deps {
		t.Error("newClientWithDeps() didn't store the dependencies")
	}
}

func TestNewClientWithDeps_FactoryError(t *testing.T) {
	expectedErr := errors.New("connection refused")

	deps := &Dependencies{
		GoSFTPClientFactory: func(config gosftp.Config) (GoSFTPClientInterface, error) {
			return nil, expectedErr
		},
	}

	config := Config{
		Host: "test.example.com",
		User: "testuser",
	}

	client, err := newClientWithDeps(config, deps)
	if err == nil {
		t.Fatal("newClientWithDeps() error = nil, want error")
	}

	if client != nil {
		t.Error("newClientWithDeps() returned non-nil client on error")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("newClientWithDeps() error doesn't wrap expected error")
	}
}

// TestBuildPrivateKeyAuthWithDeps tests private key auth with dependency injection.
func TestBuildPrivateKeyAuthWithDeps_WithKeyContent(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		PrivateKey: testPrivateKey,
	}

	auth, err := buildPrivateKeyAuthWithDeps(config, deps)
	if err != nil {
		t.Fatalf("buildPrivateKeyAuthWithDeps() error = %v, want nil", err)
	}

	if auth == nil {
		t.Fatal("buildPrivateKeyAuthWithDeps() returned nil auth method")
	}
}

func TestBuildPrivateKeyAuthWithDeps_WithKeyPath(t *testing.T) {
	// Create a temporary key file
	tmpFile, err := os.CreateTemp("", "test-key-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testPrivateKey); err != nil {
		t.Fatalf("Failed to write key: %v", err)
	}
	tmpFile.Close()

	deps := &Dependencies{
		FileReader: os.ReadFile,
	}

	config := Config{
		KeyPath: tmpFile.Name(),
	}

	auth, err := buildPrivateKeyAuthWithDeps(config, deps)
	if err != nil {
		t.Fatalf("buildPrivateKeyAuthWithDeps() error = %v, want nil", err)
	}

	if auth == nil {
		t.Fatal("buildPrivateKeyAuthWithDeps() returned nil auth method")
	}
}

func TestBuildPrivateKeyAuthWithDeps_FileReadError(t *testing.T) {
	expectedErr := errors.New("file not found")

	deps := &Dependencies{
		FileReader: func(path string) ([]byte, error) {
			return nil, expectedErr
		},
	}

	config := Config{
		KeyPath: "/nonexistent/key",
	}

	auth, err := buildPrivateKeyAuthWithDeps(config, deps)
	if err == nil {
		t.Fatal("buildPrivateKeyAuthWithDeps() error = nil, want error")
	}

	if auth != nil {
		t.Error("buildPrivateKeyAuthWithDeps() returned non-nil auth on error")
	}
}

func TestBuildPrivateKeyAuthWithDeps_NoKeyProvided(t *testing.T) {
	deps := DefaultDependencies()
	config := Config{}

	auth, err := buildPrivateKeyAuthWithDeps(config, deps)
	if err == nil {
		t.Fatal("buildPrivateKeyAuthWithDeps() error = nil, want error")
	}

	if auth != nil {
		t.Error("buildPrivateKeyAuthWithDeps() returned non-nil auth on error")
	}
}

// TestBuildHostKeyCallbackWithDeps tests host key callback with dependency injection.
func TestBuildHostKeyCallbackWithDeps_InsecureIgnoreHostKey(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		InsecureIgnoreHostKey: true,
	}

	callback, err := buildHostKeyCallbackWithDeps(config, deps)
	if err != nil {
		t.Fatalf("buildHostKeyCallbackWithDeps() error = %v, want nil", err)
	}

	if callback == nil {
		t.Fatal("buildHostKeyCallbackWithDeps() returned nil callback")
	}
}

func TestBuildHostKeyCallbackWithDeps_KnownHostsFileNotFound(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		InsecureIgnoreHostKey: false,
		KnownHostsFile:        "/nonexistent/known_hosts",
	}

	callback, err := buildHostKeyCallbackWithDeps(config, deps)
	if err == nil {
		t.Fatal("buildHostKeyCallbackWithDeps() error = nil, want error")
	}

	if callback != nil {
		t.Error("buildHostKeyCallbackWithDeps() returned non-nil callback on error")
	}
}

func TestBuildHostKeyCallbackWithDeps_NoKnownHostsAndNoDefault(t *testing.T) {
	deps := &Dependencies{
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		InsecureIgnoreHostKey: false,
		KnownHostsFile:        "",
	}

	callback, err := buildHostKeyCallbackWithDeps(config, deps)
	if err == nil {
		t.Fatal("buildHostKeyCallbackWithDeps() error = nil, want error")
	}

	if callback != nil {
		t.Error("buildHostKeyCallbackWithDeps() returned non-nil callback on error")
	}
}

// TestBuildAuthMethodsWithDeps tests auth method building with dependency injection.
func TestBuildAuthMethodsWithDeps_Password(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		Password: "testpass",
	}

	methods, err := buildAuthMethodsWithDeps(config, deps)
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDeps() error = %v, want nil", err)
	}

	if len(methods) == 0 {
		t.Fatal("buildAuthMethodsWithDeps() returned no auth methods")
	}
}

func TestBuildAuthMethodsWithDeps_PrivateKey(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		PrivateKey: testPrivateKey,
	}

	methods, err := buildAuthMethodsWithDeps(config, deps)
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDeps() error = %v, want nil", err)
	}

	if len(methods) == 0 {
		t.Fatal("buildAuthMethodsWithDeps() returned no auth methods")
	}
}

func TestBuildAuthMethodsWithDeps_PasswordMissing(t *testing.T) {
	deps := DefaultDependencies()

	config := Config{
		AuthMethod: AuthMethodPassword,
		// Password is intentionally empty
	}

	methods, err := buildAuthMethodsWithDeps(config, deps)
	if err == nil {
		t.Fatal("buildAuthMethodsWithDeps() error = nil, want error for missing password")
	}

	if methods != nil {
		t.Error("buildAuthMethodsWithDeps() returned non-nil methods on error")
	}
}

// TestConnectToBastionWithDeps tests bastion connection with dependency injection.
func TestConnectToBastionWithDeps_PasswordAuth(t *testing.T) {
	sshDialCalled := false

	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			sshDialCalled = true
			if network != "tcp" {
				t.Errorf("Expected network tcp, got %s", network)
			}
			if addr != "bastion.example.com:22" {
				t.Errorf("Expected addr bastion.example.com:22, got %s", addr)
			}
			if config.User != "bastionuser" {
				t.Errorf("Expected user bastionuser, got %s", config.User)
			}
			// Return an error since we can't create a real SSH client
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		BastionHost:           "bastion.example.com",
		BastionUser:           "bastionuser",
		BastionPassword:       "bastionpass",
		InsecureIgnoreHostKey: true,
	}

	_, err := connectToBastionWithDeps(config, 30*time.Second, deps)
	// We expect an error because we're mocking the SSH dial
	if err == nil {
		t.Fatal("connectToBastionWithDeps() error = nil, expected mock connection error")
	}

	if !sshDialCalled {
		t.Error("connectToBastionWithDeps() didn't call SSHDialer")
	}
}

func TestConnectToBastionWithDeps_KeyAuth(t *testing.T) {
	sshDialCalled := false

	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			sshDialCalled = true
			return nil, errors.New("mock connection")
		},
		FileReader: func(path string) ([]byte, error) {
			return []byte(testPrivateKey), nil
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		BastionHost:           "bastion.example.com",
		BastionUser:           "bastionuser",
		BastionKeyPath:        "/path/to/key",
		InsecureIgnoreHostKey: true,
	}

	_, err := connectToBastionWithDeps(config, 30*time.Second, deps)
	if err == nil {
		t.Fatal("connectToBastionWithDeps() error = nil, expected mock connection error")
	}

	if !sshDialCalled {
		t.Error("connectToBastionWithDeps() didn't call SSHDialer")
	}
}

func TestConnectToBastionWithDeps_NoKeyConfigured(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			t.Fatal("SSHDialer should not be called")
			return nil, nil
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		BastionHost:           "bastion.example.com",
		BastionUser:           "bastionuser",
		InsecureIgnoreHostKey: true,
		// No password or key configured
	}

	_, err := connectToBastionWithDeps(config, 30*time.Second, deps)
	if err == nil {
		t.Fatal("connectToBastionWithDeps() error = nil, expected 'no SSH key configured' error")
	}
}

func TestConnectToBastionWithDeps_DefaultPort(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			if addr != "bastion.example.com:22" {
				t.Errorf("Expected default port 22, got %s", addr)
			}
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		BastionHost:           "bastion.example.com",
		BastionPassword:       "pass",
		InsecureIgnoreHostKey: true,
		// Port is 0, should default to 22
	}

	_, _ = connectToBastionWithDeps(config, 30*time.Second, deps)
}

func TestConnectToBastionWithDeps_DefaultUser(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			if config.User != "mainuser" {
				t.Errorf("Expected user mainuser (from config.User), got %s", config.User)
			}
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	config := Config{
		BastionHost:           "bastion.example.com",
		BastionPassword:       "pass",
		User:                  "mainuser",
		InsecureIgnoreHostKey: true,
		// BastionUser is empty, should default to User
	}

	_, _ = connectToBastionWithDeps(config, 30*time.Second, deps)
}

// TestRunCommandWithDeps tests command execution with dependency injection.
func TestRunCommandWithDeps_ContextCancelled(t *testing.T) {
	deps := DefaultDependencies()

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			Password:              "testpass",
			InsecureIgnoreHostKey: true,
		},
		deps: deps,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	stdout, stderr, err := client.runCommandWithDeps(ctx, "echo hello", deps)
	if err == nil {
		t.Fatal("runCommandWithDeps() error = nil, expected context cancelled error")
	}

	if stdout != "" || stderr != "" {
		t.Errorf("runCommandWithDeps() returned non-empty output on cancelled context")
	}
}

func TestRunCommandWithDeps_AuthBuildError(t *testing.T) {
	deps := &Dependencies{
		FileReader: func(path string) ([]byte, error) {
			return nil, errors.New("file not found")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			KeyPath:               "/nonexistent/key",
			InsecureIgnoreHostKey: true,
		},
		deps: deps,
	}

	stdout, stderr, err := client.runCommandWithDeps(context.Background(), "echo hello", deps)
	if err == nil {
		t.Fatal("runCommandWithDeps() error = nil, expected auth build error")
	}

	if stdout != "" || stderr != "" {
		t.Errorf("runCommandWithDeps() returned non-empty output on error")
	}
}

func TestRunCommandWithDeps_HostKeyCallbackError(t *testing.T) {
	deps := &Dependencies{
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:       "test.example.com",
			User:       "testuser",
			Password:   "testpass",
			PrivateKey: testPrivateKey,
			// InsecureIgnoreHostKey is false and no known_hosts file
		},
		deps: deps,
	}

	stdout, stderr, err := client.runCommandWithDeps(context.Background(), "echo hello", deps)
	if err == nil {
		t.Fatal("runCommandWithDeps() error = nil, expected host key callback error")
	}

	if stdout != "" || stderr != "" {
		t.Errorf("runCommandWithDeps() returned non-empty output on error")
	}
}

func TestRunCommandWithDeps_SSHDialError(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			return nil, errors.New("connection refused")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			Password:              "testpass",
			InsecureIgnoreHostKey: true,
		},
		deps: deps,
	}

	stdout, stderr, err := client.runCommandWithDeps(context.Background(), "echo hello", deps)
	if err == nil {
		t.Fatal("runCommandWithDeps() error = nil, expected SSH dial error")
	}

	if stdout != "" || stderr != "" {
		t.Errorf("runCommandWithDeps() returned non-empty output on dial error")
	}
}

func TestRunCommandWithDeps_TimeoutFromConfig(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			if config.Timeout != 60*time.Second {
				t.Errorf("Expected timeout 60s, got %v", config.Timeout)
			}
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			Password:              "testpass",
			Timeout:               60 * time.Second,
			InsecureIgnoreHostKey: true,
		},
		deps: deps,
	}

	_, _, _ = client.runCommandWithDeps(context.Background(), "echo hello", deps)
}

func TestRunCommandWithDeps_DefaultTimeout(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			if config.Timeout != 30*time.Second {
				t.Errorf("Expected default timeout 30s, got %v", config.Timeout)
			}
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			Password:              "testpass",
			InsecureIgnoreHostKey: true,
			// Timeout is 0, should default to 30s
		},
		deps: deps,
	}

	_, _, _ = client.runCommandWithDeps(context.Background(), "echo hello", deps)
}

func TestRunCommandWithDeps_DefaultPort(t *testing.T) {
	deps := &Dependencies{
		SSHDialer: func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
			if addr != "test.example.com:22" {
				t.Errorf("Expected default port 22, got %s", addr)
			}
			return nil, errors.New("mock connection")
		},
		HomeDir: func() (string, error) {
			return "", errors.New("no home dir")
		},
		FileStat: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &Client{
		config: Config{
			Host:                  "test.example.com",
			User:                  "testuser",
			Password:              "testpass",
			InsecureIgnoreHostKey: true,
			// Port is 0, should default to 22
		},
		deps: deps,
	}

	_, _, _ = client.runCommandWithDeps(context.Background(), "echo hello", deps)
}

// TestClientFactory tests the client factory.
func TestNewClientFactory_WithNilDeps(t *testing.T) {
	factory := NewClientFactory(nil)
	if factory == nil {
		t.Fatal("NewClientFactory(nil) returned nil")
	}

	if factory.deps == nil {
		t.Fatal("NewClientFactory(nil) should use default dependencies")
	}
}

func TestNewClientFactory_WithCustomDeps(t *testing.T) {
	customDeps := &Dependencies{
		GoSFTPClientFactory: func(config gosftp.Config) (GoSFTPClientInterface, error) {
			return nil, errors.New("custom error")
		},
	}

	factory := NewClientFactory(customDeps)
	if factory == nil {
		t.Fatal("NewClientFactory() returned nil")
	}

	if factory.deps != customDeps {
		t.Fatal("NewClientFactory() didn't use custom dependencies")
	}
}
