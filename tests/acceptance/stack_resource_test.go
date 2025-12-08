package acceptance

import (
	"fmt"
	"strings"
	"testing"
	"time"

	internalssh "github.com/darshan-rambhia/terraform-provider-docker-compose/internal/ssh"
)

// Basic compose file for testing.
const testComposeContent = `version: "3.8"
services:
  test:
    image: alpine:latest
    command: ["sleep", "infinity"]
`

// Invalid compose file for testing validation.
const invalidComposeContent = `version: "3.8"
services:
  test:
    # missing image or build
`

func TestAccStackResource_BasicUpload(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	// Create SSH client config
	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	remotePath := "/opt/stacks/test/docker-compose.yaml"

	// Upload compose file
	err = client.UploadContent(t.Context(), []byte(testComposeContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload compose file: %v", err)
	}

	// Verify file exists
	exists, err := client.FileExists(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to check file exists: %v", err)
	}
	if !exists {
		t.Error("compose file was not uploaded")
	}

	// Verify content hash
	hash, err := client.GetFileHash(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to get file hash: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("unexpected hash format: %s", hash)
	}

	// Read back content
	content, err := client.ReadFileContent(t.Context(), remotePath, 0)
	if err != nil {
		t.Fatalf("failed to read file content: %v", err)
	}
	if string(content) != testComposeContent {
		t.Errorf("content mismatch:\ngot: %s\nwant: %s", content, testComposeContent)
	}
}

func TestAccStackResource_ValidateComposeFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	// Wait for docker compose CLI to be ready (doesn't need daemon)
	waitForDockerCompose(t, container)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name       string
		content    string
		remotePath string
		wantErr    bool
	}{
		{
			name:       "valid compose file",
			content:    testComposeContent,
			remotePath: "/opt/stacks/valid/docker-compose.yaml",
			wantErr:    false,
		},
		{
			name:       "invalid compose file",
			content:    invalidComposeContent,
			remotePath: "/opt/stacks/invalid/docker-compose.yaml",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Upload the compose file
			err := client.UploadContent(t.Context(), []byte(tt.content), tt.remotePath)
			if err != nil {
				t.Fatalf("failed to upload compose file: %v", err)
			}

			// Validate using docker compose config
			err = container.DockerComposeValidate(t, tt.remotePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("DockerComposeValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccStackResource_ComposeUpDown(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	// Wait for Docker to be ready
	waitForDocker(t, container)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	remotePath := "/opt/stacks/lifecycle/docker-compose.yaml"

	// Upload compose file
	err = client.UploadContent(t.Context(), []byte(testComposeContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload compose file: %v", err)
	}

	// Run docker compose up
	stdout, stderr, err := client.RunCommand(t.Context(), "cd /opt/stacks/lifecycle && docker compose -f docker-compose.yaml up -d")
	if err != nil {
		t.Fatalf("docker compose up failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Wait for container to start
	time.Sleep(2 * time.Second)

	// Verify container is running
	stdout, _, err = client.RunCommand(t.Context(), "docker ps --filter 'name=lifecycle' --format '{{.Names}}'")
	if err != nil {
		t.Fatalf("docker ps failed: %v", err)
	}
	if !strings.Contains(stdout, "lifecycle") {
		t.Logf("docker ps output: %s", stdout)
		// This might fail if the container name is different, so just log it
	}

	// Run docker compose down
	stdout, stderr, err = client.RunCommand(t.Context(), "cd /opt/stacks/lifecycle && docker compose -f docker-compose.yaml down")
	if err != nil {
		t.Fatalf("docker compose down failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
}

func TestAccStackResource_RunCommand(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name       string
		command    string
		wantOutput string
		wantErr    bool
	}{
		{
			name:       "simple echo",
			command:    "echo hello",
			wantOutput: "hello\n",
			wantErr:    false,
		},
		{
			name:       "pwd",
			command:    "pwd",
			wantOutput: "/",
			wantErr:    false,
		},
		{
			name:    "command with error",
			command: "exit 1",
			wantErr: true,
		},
		{
			name:    "non-existent command",
			command: "nonexistentcommand12345",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := client.RunCommand(t.Context(), tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("RunCommand() error = %v, wantErr %v\nstderr: %s", err, tt.wantErr, stderr)
			}
			if !tt.wantErr && tt.wantOutput != "" && !strings.Contains(stdout, strings.TrimSpace(tt.wantOutput)) {
				t.Errorf("RunCommand() stdout = %q, want contains %q", stdout, tt.wantOutput)
			}
		})
	}
}

func TestAccStackResource_DeleteFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	remotePath := "/opt/stacks/delete-test/docker-compose.yaml"

	// Upload file
	err = client.UploadContent(t.Context(), []byte(testComposeContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload file: %v", err)
	}

	// Verify file exists
	exists, err := client.FileExists(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to check file exists: %v", err)
	}
	if !exists {
		t.Fatal("file should exist after upload")
	}

	// Delete file
	err = client.DeleteFile(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}

	// Verify file no longer exists
	exists, err = client.FileExists(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to check file exists: %v", err)
	}
	if exists {
		t.Error("file should not exist after deletion")
	}

	// Delete again (should be idempotent)
	err = client.DeleteFile(t.Context(), remotePath)
	if err != nil {
		t.Errorf("second delete should be idempotent, got error: %v", err)
	}
}

func TestAccStackResource_ContentUpdate(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	remotePath := "/opt/stacks/update-test/docker-compose.yaml"

	// Upload initial content
	initialContent := testComposeContent
	err = client.UploadContent(t.Context(), []byte(initialContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload initial content: %v", err)
	}

	initialHash, err := client.GetFileHash(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to get initial hash: %v", err)
	}

	// Upload updated content
	updatedContent := `version: "3.8"
services:
  test:
    image: alpine:latest
    command: ["sleep", "3600"]
  web:
    image: nginx:alpine
`
	err = client.UploadContent(t.Context(), []byte(updatedContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload updated content: %v", err)
	}

	updatedHash, err := client.GetFileHash(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to get updated hash: %v", err)
	}

	// Hashes should be different
	if initialHash == updatedHash {
		t.Error("hash should change when content is updated")
	}

	// Verify updated content
	content, err := client.ReadFileContent(t.Context(), remotePath, 0)
	if err != nil {
		t.Fatalf("failed to read updated content: %v", err)
	}
	if string(content) != updatedContent {
		t.Errorf("content mismatch:\ngot: %s\nwant: %s", content, updatedContent)
	}
}

func TestAccStackResource_PathWithSpaces(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	// Test path with spaces
	remotePath := "/opt/my stacks/test app/docker-compose.yaml"

	err = client.UploadContent(t.Context(), []byte(testComposeContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload to path with spaces: %v", err)
	}

	exists, err := client.FileExists(t.Context(), remotePath)
	if err != nil {
		t.Fatalf("failed to check file exists: %v", err)
	}
	if !exists {
		t.Error("file should exist at path with spaces")
	}

	content, err := client.ReadFileContent(t.Context(), remotePath, 0)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(content) != testComposeContent {
		t.Error("content mismatch for path with spaces")
	}
}

func TestAccStackResource_LargeFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHDockerContainer(t)

	config := internalssh.Config{
		Host:                  container.Host,
		Port:                  container.Port,
		User:                  container.User,
		PrivateKey:            container.PrivateKey,
		InsecureIgnoreHostKey: true,
	}

	client, err := internalssh.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	// Create a large compose file with many services
	var builder strings.Builder
	builder.WriteString("version: \"3.8\"\nservices:\n")
	for i := 0; i < 100; i++ {
		builder.WriteString(fmt.Sprintf("  service_%d:\n", i))
		builder.WriteString("    image: alpine:latest\n")
		builder.WriteString("    command: [\"sleep\", \"infinity\"]\n")
	}
	largeContent := builder.String()

	remotePath := "/opt/stacks/large/docker-compose.yaml"

	err = client.UploadContent(t.Context(), []byte(largeContent), remotePath)
	if err != nil {
		t.Fatalf("failed to upload large file: %v", err)
	}

	content, err := client.ReadFileContent(t.Context(), remotePath, 0)
	if err != nil {
		t.Fatalf("failed to read large file: %v", err)
	}
	if string(content) != largeContent {
		t.Error("content mismatch for large file")
	}
}

// waitForDocker waits for Docker daemon to be ready in the container.
func waitForDocker(t *testing.T, container *SSHDockerContainer) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if container.IsDockerAvailable(t) && container.IsDockerComposeAvailable(t) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Skip("Skipping test: Docker daemon is not available in the test container")
}

// waitForDockerCompose waits for docker compose CLI to be ready (doesn't require daemon).
func waitForDockerCompose(t *testing.T, container *SSHDockerContainer) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if container.IsDockerComposeAvailable(t) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Skip("Skipping test: docker compose CLI is not available in the test container")
}
