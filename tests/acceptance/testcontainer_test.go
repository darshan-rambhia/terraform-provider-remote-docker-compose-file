package acceptance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// Test flags.
var (
	parallelContainers = flag.Int("parallel-containers", 1, "Number of SSH containers for parallel test execution (1 = sequential)")
)

// Global container pool - initialized lazily.
var pool *ContainerPool

// GetPool returns the global container pool, creating it if necessary.
func GetPool() *ContainerPool {
	if pool == nil {
		pool = NewContainerPool(*parallelContainers)
	}
	return pool
}

// ClosePool closes the global container pool.
func ClosePool() {
	if pool != nil {
		pool.Close()
		pool = nil
	}
}

// SSHDockerContainer provides a container with both SSH and Docker for integration testing.
type SSHDockerContainer struct {
	Container      testcontainers.Container
	Host           string
	Port           int
	User           string
	PrivateKey     string
	PrivateKeyPath string
}

// generateSSHKeyPair generates an RSA key pair for SSH testing.
func generateSSHKeyPair(t *testing.T) (privateKeyPEM, publicKeySSH string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}
	publicKeySSH = string(ssh.MarshalAuthorizedKey(publicKey))

	return privateKeyPEM, publicKeySSH
}

// SetupSSHDockerContainer returns an SSH+Docker container for testing.
func SetupSSHDockerContainer(t *testing.T) *SSHDockerContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	return GetPool().Acquire(t)
}

// SetupIsolatedContainer creates a new container just for this test (not from pool).
func SetupIsolatedContainer(t *testing.T) *SSHDockerContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	return createNewContainer(t)
}

// createNewContainer creates a new container for a single test.
func createNewContainer(t *testing.T) *SSHDockerContainer {
	t.Helper()

	ctx := context.Background()
	privateKey, publicKey := generateSSHKeyPair(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "./testdata",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"22/tcp"},
		Env: map[string]string{
			"PUBLIC_KEY": publicKey,
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("22/tcp"),
			wait.ForLog("Server listening on").WithStartupTimeout(60*time.Second),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get container host: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "22/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get mapped port: %v", err)
	}

	sshContainer := &SSHDockerContainer{
		Container:      container,
		Host:           host,
		Port:           mappedPort.Int(),
		User:           "testuser",
		PrivateKey:     privateKey,
		PrivateKeyPath: keyPath,
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	if err := waitForSSH(sshContainer, 30*time.Second); err != nil {
		t.Fatalf("SSH not ready: %v", err)
	}

	return sshContainer
}

// waitForSSH waits for SSH connection to be ready.
func waitForSSH(c *SSHDockerContainer, timeout time.Duration) error {
	signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)

	for time.Now().Before(deadline) {
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			client.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for SSH at %s", addr)
}

// Address returns the SSH address in host:port format.
func (c *SSHDockerContainer) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// RunCommand executes a command in the container via SSH.
func (c *SSHDockerContainer) RunCommand(t *testing.T, command string) (string, error) {
	t.Helper()
	return c.runCommand(command)
}

// runCommand is the internal implementation for running commands.
func (c *SSHDockerContainer) runCommand(command string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", c.Address(), config)
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

// ReadRemoteFile reads a file from the container.
func (c *SSHDockerContainer) ReadRemoteFile(t *testing.T, path string) (string, error) {
	t.Helper()
	return c.runCommand(fmt.Sprintf("cat %q", path))
}

// FileExists checks if a file exists in the container.
func (c *SSHDockerContainer) FileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := c.runCommand(fmt.Sprintf("test -f %q", path))
	return err == nil
}

// FileExistsNoHelper checks if a file exists without requiring *testing.T.
func (c *SSHDockerContainer) FileExistsNoHelper(path string) bool {
	_, err := c.runCommand(fmt.Sprintf("test -f %q", path))
	return err == nil
}

// ReadRemoteFileNoHelper reads a file without requiring *testing.T.
func (c *SSHDockerContainer) ReadRemoteFileNoHelper(path string) (string, error) {
	return c.runCommand(fmt.Sprintf("cat %q", path))
}

// DockerComposeUp runs docker compose up on a compose file.
func (c *SSHDockerContainer) DockerComposeUp(t *testing.T, composePath string) error {
	t.Helper()
	_, err := c.runCommand(fmt.Sprintf("cd $(dirname %q) && docker compose -f $(basename %q) up -d", composePath, composePath))
	return err
}

// DockerComposeDown runs docker compose down on a compose file.
func (c *SSHDockerContainer) DockerComposeDown(t *testing.T, composePath string) error {
	t.Helper()
	_, err := c.runCommand(fmt.Sprintf("cd $(dirname %q) && docker compose -f $(basename %q) down", composePath, composePath))
	return err
}

// DockerComposeValidate validates a compose file.
func (c *SSHDockerContainer) DockerComposeValidate(t *testing.T, composePath string) error {
	t.Helper()
	_, err := c.runCommand(fmt.Sprintf("cd $(dirname %q) && docker compose -f $(basename %q) config --quiet", composePath, composePath))
	return err
}

// IsDockerAvailable checks if Docker is available in the container.
func (c *SSHDockerContainer) IsDockerAvailable(t *testing.T) bool {
	t.Helper()
	_, err := c.runCommand("docker info")
	return err == nil
}

// IsDockerComposeAvailable checks if docker compose is available.
func (c *SSHDockerContainer) IsDockerComposeAvailable(t *testing.T) bool {
	t.Helper()
	_, err := c.runCommand("docker compose version")
	return err == nil
}

// WriteFile writes content to a file in the container.
func (c *SSHDockerContainer) WriteFile(t *testing.T, path string, content string) error {
	t.Helper()
	// Create directory and write file
	dir := filepath.Dir(path)
	_, err := c.runCommand(fmt.Sprintf("mkdir -p %q && cat > %q << 'EOFMARKER'\n%s\nEOFMARKER", dir, path, content))
	return err
}
