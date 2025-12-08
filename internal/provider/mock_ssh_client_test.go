package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/darshan-rambhia/terraform-provider-docker-compose/internal/ssh"
)

// MockSSHClient implements ssh.ClientInterface for testing.
type MockSSHClient struct {
	// File operations
	Files         map[string][]byte
	Permissions   map[string]os.FileMode
	OwnershipMap  map[string]string // path -> "owner:group"
	UploadedFiles map[string][]byte

	// Command execution
	Commands       []string
	CommandOutputs map[string]CommandResult

	// Error injection
	CloseError         error
	UploadFileError    error
	UploadContentError error
	GetFileHashError   error
	SetAttributesError error
	DeleteFileError    error
	FileExistsError    error
	GetFileInfoError   error
	ReadContentError   error
	RunCommandError    error
}

// CommandResult represents the result of a command execution.
type CommandResult struct {
	Stdout string
	Stderr string
	Err    error
}

var _ ssh.ClientInterface = (*MockSSHClient)(nil)

// NewMockSSHClient creates a new mock SSH client.
func NewMockSSHClient() *MockSSHClient {
	return &MockSSHClient{
		Files:          make(map[string][]byte),
		Permissions:    make(map[string]os.FileMode),
		OwnershipMap:   make(map[string]string),
		UploadedFiles:  make(map[string][]byte),
		Commands:       make([]string, 0),
		CommandOutputs: make(map[string]CommandResult),
	}
}

// NewMockSSHClientFactory creates an SSHClientFactory that returns mock clients.
func NewMockSSHClientFactory(mock *MockSSHClient) SSHClientFactory {
	return func(config ssh.Config) (ssh.ClientInterface, error) {
		return mock, nil
	}
}

// NewMockSSHClientFactoryWithError creates an SSHClientFactory that returns an error.
func NewMockSSHClientFactoryWithError(err error) SSHClientFactory {
	return func(config ssh.Config) (ssh.ClientInterface, error) {
		return nil, err
	}
}

func (m *MockSSHClient) Close() error {
	return m.CloseError
}

func (m *MockSSHClient) UploadFile(ctx context.Context, localPath, remotePath string) error {
	if m.UploadFileError != nil {
		return m.UploadFileError
	}
	// Simulate reading local file (for testing, we just note the operation)
	m.Files[remotePath] = []byte("uploaded from " + localPath)
	return nil
}

func (m *MockSSHClient) UploadContent(ctx context.Context, content []byte, remotePath string) error {
	if m.UploadContentError != nil {
		return m.UploadContentError
	}
	m.Files[remotePath] = content
	m.UploadedFiles[remotePath] = content
	return nil
}

func (m *MockSSHClient) GetFileHash(ctx context.Context, remotePath string) (string, error) {
	if m.GetFileHashError != nil {
		return "", m.GetFileHashError
	}
	content, exists := m.Files[remotePath]
	if !exists {
		return "", os.ErrNotExist
	}
	return hashContentBytes(content), nil
}

func (m *MockSSHClient) SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error {
	if m.SetAttributesError != nil {
		return m.SetAttributesError
	}
	if _, exists := m.Files[remotePath]; !exists {
		return os.ErrNotExist
	}
	if owner != "" || group != "" {
		m.OwnershipMap[remotePath] = owner + ":" + group
	}
	if mode != "" {
		// Parse mode as octal
		var modeVal os.FileMode
		for _, c := range mode {
			modeVal = modeVal*8 + os.FileMode(c-'0')
		}
		m.Permissions[remotePath] = modeVal
	}
	return nil
}

func (m *MockSSHClient) DeleteFile(ctx context.Context, remotePath string) error {
	if m.DeleteFileError != nil {
		return m.DeleteFileError
	}
	delete(m.Files, remotePath)
	delete(m.UploadedFiles, remotePath)
	return nil
}

func (m *MockSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	if m.FileExistsError != nil {
		return false, m.FileExistsError
	}
	_, exists := m.Files[remotePath]
	return exists, nil
}

func (m *MockSSHClient) GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error) {
	if m.GetFileInfoError != nil {
		return nil, m.GetFileInfoError
	}
	content, exists := m.Files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}
	mode := m.Permissions[remotePath]
	if mode == 0 {
		mode = 0644
	}
	return &mockFileInfo{
		name: remotePath,
		size: int64(len(content)),
		mode: mode,
	}, nil
}

func (m *MockSSHClient) ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	if m.ReadContentError != nil {
		return nil, m.ReadContentError
	}
	content, exists := m.Files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}
	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return content[:maxBytes], nil
	}
	return content, nil
}

func (m *MockSSHClient) RunCommand(ctx context.Context, command string) (string, string, error) {
	m.Commands = append(m.Commands, command)

	if m.RunCommandError != nil {
		return "", "", m.RunCommandError
	}

	// Check for specific command output
	if result, exists := m.CommandOutputs[command]; exists {
		return result.Stdout, result.Stderr, result.Err
	}

	// Check for pattern matches (contains)
	for pattern, result := range m.CommandOutputs {
		if containsString(command, pattern) {
			return result.Stdout, result.Stderr, result.Err
		}
	}

	// Default: command succeeds with no output
	return "", "", nil
}

// Helper methods for test setup

// SetCommandOutput sets the output for a specific command.
func (m *MockSSHClient) SetCommandOutput(command, stdout, stderr string, err error) {
	m.CommandOutputs[command] = CommandResult{
		Stdout: stdout,
		Stderr: stderr,
		Err:    err,
	}
}

// SetCommandError sets an error for any command containing the pattern.
func (m *MockSSHClient) SetCommandError(pattern string, stderr string, err error) {
	m.CommandOutputs[pattern] = CommandResult{
		Stderr: stderr,
		Err:    err,
	}
}

// AddFile adds a file to the mock filesystem.
func (m *MockSSHClient) AddFile(path string, content []byte) {
	m.Files[path] = content
}

// HasFile checks if a file exists in the mock filesystem.
func (m *MockSSHClient) HasFile(path string) bool {
	_, exists := m.Files[path]
	return exists
}

// GetUploadedContent returns the content that was uploaded to a path.
func (m *MockSSHClient) GetUploadedContent(path string) ([]byte, bool) {
	content, exists := m.UploadedFiles[path]
	return content, exists
}

// GetCommands returns all commands that were executed.
func (m *MockSSHClient) GetCommands() []string {
	return m.Commands
}

// CommandWasExecuted checks if a command containing the pattern was executed.
func (m *MockSSHClient) CommandWasExecuted(pattern string) bool {
	for _, cmd := range m.Commands {
		if containsString(cmd, pattern) {
			return true
		}
	}
	return false
}

// Reset clears all state from the mock.
func (m *MockSSHClient) Reset() {
	m.Files = make(map[string][]byte)
	m.Permissions = make(map[string]os.FileMode)
	m.OwnershipMap = make(map[string]string)
	m.UploadedFiles = make(map[string][]byte)
	m.Commands = make([]string, 0)
	m.CommandOutputs = make(map[string]CommandResult)
	m.CloseError = nil
	m.UploadFileError = nil
	m.UploadContentError = nil
	m.GetFileHashError = nil
	m.SetAttributesError = nil
	m.DeleteFileError = nil
	m.FileExistsError = nil
	m.GetFileInfoError = nil
	m.ReadContentError = nil
	m.RunCommandError = nil
}

// mockFileInfo implements os.FileInfo for testing.
type mockFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }

// Helper function to compute hash.
func hashContentBytes(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Helper function to check string containment.
func containsString(s, substr string) bool {
	return len(substr) <= len(s) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Common test errors.
var (
	ErrMockSSHConnection = errors.New("mock SSH connection error")
	ErrMockUpload        = errors.New("mock upload error")
	ErrMockDelete        = errors.New("mock delete error")
	ErrMockCommand       = errors.New("mock command execution error")
	ErrMockValidation    = errors.New("mock validation error")
)
