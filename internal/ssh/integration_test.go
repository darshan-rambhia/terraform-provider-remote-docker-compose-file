//go:build integration
// +build integration

package ssh

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Integration tests require a running SSH server.
// Run with: go test -tags=integration -v ./internal/ssh
//
// These tests use Docker to spin up an SSH server for testing.
// Prerequisites:
//   - Docker must be installed and running
//   - Port 2222 must be available
//
// To run manually:
//   docker run -d --name ssh-test -p 2222:22 -e PASSWORD_ACCESS=true \
//     -e USER_NAME=testuser -e USER_PASSWORD=testpass linuxserver/openssh-server
//   go test -tags=integration -v ./internal/ssh
//   docker stop ssh-test && docker rm ssh-test

const (
	testHost        = "localhost"
	testPort        = 2222
	testUser        = "testuser"
	testPassword    = "testpass"
	containerName   = "ssh-test-server"
	containerImage  = "linuxserver/openssh-server"
	startupWaitTime = 10 * time.Second
)

var sshServerRunning = false

// setupSSHServer starts a Docker container with an SSH server.
func setupSSHServer(t *testing.T) {
	t.Helper()

	if sshServerRunning {
		return
	}

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not available, skipping integration tests")
	}

	// Stop any existing container
	exec.Command("docker", "stop", containerName).Run()
	exec.Command("docker", "rm", containerName).Run()

	// Start SSH server container
	cmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", "2222:22",
		"-e", "PASSWORD_ACCESS=true",
		"-e", "USER_NAME="+testUser,
		"-e", "USER_PASSWORD="+testPassword,
		"-e", "SUDO_ACCESS=true",
		containerImage,
	)

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to start SSH server container: %v", err)
	}

	// Wait for SSH server to be ready
	t.Log("Waiting for SSH server to start...")
	time.Sleep(startupWaitTime)

	sshServerRunning = true
}

// teardownSSHServer stops and removes the Docker container.
func teardownSSHServer(t *testing.T) {
	t.Helper()

	exec.Command("docker", "stop", containerName).Run()
	exec.Command("docker", "rm", containerName).Run()
	sshServerRunning = false
}

// TestIntegration_NewClient tests creating a real SSH client.
func TestIntegration_NewClient(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

// TestIntegration_RunCommand tests running a command over SSH.
func TestIntegration_RunCommand(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	stdout, stderr, err := client.RunCommand(ctx, "echo 'hello world'")
	if err != nil {
		t.Fatalf("RunCommand() error = %v, stderr = %s", err, stderr)
	}

	if !strings.Contains(stdout, "hello world") {
		t.Errorf("RunCommand() stdout = %q, want 'hello world'", stdout)
	}
}

// TestIntegration_RunCommand_WithError tests running a command that fails.
func TestIntegration_RunCommand_WithError(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	_, stderr, err := client.RunCommand(ctx, "exit 1")
	if err == nil {
		t.Error("RunCommand() expected error for 'exit 1'")
	}

	// stderr might be empty for a simple exit command
	_ = stderr
}

// TestIntegration_UploadAndReadContent tests file upload and reading.
func TestIntegration_UploadAndReadContent(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	content := []byte("test content for integration test")
	remotePath := "/tmp/integration-test-file.txt"

	// Upload content
	if err := client.UploadContent(ctx, content, remotePath); err != nil {
		t.Fatalf("UploadContent() error = %v", err)
	}

	// Check file exists
	exists, err := client.FileExists(ctx, remotePath)
	if err != nil {
		t.Fatalf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("FileExists() returned false, expected true")
	}

	// Read content back
	readContent, err := client.ReadFileContent(ctx, remotePath, 1024)
	if err != nil {
		t.Fatalf("ReadFileContent() error = %v", err)
	}

	if string(readContent) != string(content) {
		t.Errorf("ReadFileContent() = %q, want %q", string(readContent), string(content))
	}

	// Get file hash
	hash, err := client.GetFileHash(ctx, remotePath)
	if err != nil {
		t.Fatalf("GetFileHash() error = %v", err)
	}
	if hash == "" {
		t.Error("GetFileHash() returned empty hash")
	}

	// Delete file
	if err := client.DeleteFile(ctx, remotePath); err != nil {
		t.Fatalf("DeleteFile() error = %v", err)
	}

	// Verify file is deleted
	exists, err = client.FileExists(ctx, remotePath)
	if err != nil {
		t.Fatalf("FileExists() after delete error = %v", err)
	}
	if exists {
		t.Error("FileExists() after delete returned true, expected false")
	}
}

// TestIntegration_GetFileInfo tests getting file information.
func TestIntegration_GetFileInfo(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	content := []byte("test content")
	remotePath := "/tmp/integration-test-info.txt"

	// Upload content
	if err := client.UploadContent(ctx, content, remotePath); err != nil {
		t.Fatalf("UploadContent() error = %v", err)
	}
	defer client.DeleteFile(ctx, remotePath)

	// Get file info
	info, err := client.GetFileInfo(ctx, remotePath)
	if err != nil {
		t.Fatalf("GetFileInfo() error = %v", err)
	}

	if info.Size() != int64(len(content)) {
		t.Errorf("GetFileInfo().Size() = %d, want %d", info.Size(), len(content))
	}

	if info.Name() != "integration-test-info.txt" {
		t.Errorf("GetFileInfo().Name() = %q, want 'integration-test-info.txt'", info.Name())
	}
}

// TestIntegration_UploadFile tests uploading a local file.
func TestIntegration_UploadFile(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	// Create a temporary local file
	tmpFile, err := os.CreateTemp("", "integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "local file content for upload test"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	remotePath := "/tmp/integration-test-upload.txt"

	// Upload file
	if err := client.UploadFile(ctx, tmpFile.Name(), remotePath); err != nil {
		t.Fatalf("UploadFile() error = %v", err)
	}
	defer client.DeleteFile(ctx, remotePath)

	// Verify file content
	readContent, err := client.ReadFileContent(ctx, remotePath, 1024)
	if err != nil {
		t.Fatalf("ReadFileContent() error = %v", err)
	}

	if string(readContent) != content {
		t.Errorf("ReadFileContent() = %q, want %q", string(readContent), content)
	}
}

// TestIntegration_ContextTimeout tests that context timeout is respected.
func TestIntegration_ContextTimeout(t *testing.T) {
	setupSSHServer(t)
	defer teardownSSHServer(t)

	config := Config{
		Host:                  testHost,
		Port:                  testPort,
		User:                  testUser,
		Password:              testPassword,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	// Create a context that will be cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = client.RunCommand(ctx, "echo hello")
	if err == nil {
		t.Error("RunCommand() with cancelled context should return error")
	}
}

// TestIntegration_ConnectionFailure tests connection to non-existent host.
func TestIntegration_ConnectionFailure(t *testing.T) {
	config := Config{
		Host:                  "nonexistent.invalid",
		Port:                  22,
		User:                  "testuser",
		Password:              "testpass",
		InsecureIgnoreHostKey: true,
		Timeout:               5 * time.Second,
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() to nonexistent host should return error")
	}
}
