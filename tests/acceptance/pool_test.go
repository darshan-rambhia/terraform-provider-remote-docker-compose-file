package acceptance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// ContainerPool manages a pool of SSH containers for parallel test execution.
type ContainerPool struct {
	size          int
	containers    chan *SSHDockerContainer
	allContainers []*SSHDockerContainer
	initOnce      sync.Once
	initErr       error
	mu            sync.Mutex
	closed        bool
}

// NewContainerPool creates a new container pool with the specified size.
func NewContainerPool(size int) *ContainerPool {
	if size < 1 {
		size = 1
	}
	return &ContainerPool{
		size:       size,
		containers: make(chan *SSHDockerContainer, size),
	}
}

// initialize creates all containers in the pool.
func (p *ContainerPool) initialize(t *testing.T) error {
	p.initOnce.Do(func() {
		t.Logf("Initializing container pool with %d containers...", p.size)

		p.allContainers = make([]*SSHDockerContainer, 0, p.size)

		var wg sync.WaitGroup
		errors := make([]error, p.size)
		containers := make([]*SSHDockerContainer, p.size)

		for i := 0; i < p.size; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				container, err := createPoolContainer(t, idx)
				if err != nil {
					errors[idx] = err
					return
				}
				containers[idx] = container
			}(i)
		}

		wg.Wait()

		for i, err := range errors {
			if err != nil {
				p.initErr = fmt.Errorf("failed to create container %d: %w", i, err)
				for _, c := range containers {
					if c != nil && c.Container != nil {
						_ = c.Container.Terminate(context.Background())
					}
				}
				return
			}
		}

		for _, c := range containers {
			p.allContainers = append(p.allContainers, c)
			p.containers <- c
		}

		t.Logf("Container pool initialized with %d containers", p.size)
	})

	return p.initErr
}

// Acquire gets a container from the pool.
func (p *ContainerPool) Acquire(t *testing.T) *SSHDockerContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	if err := p.initialize(t); err != nil {
		t.Fatalf("failed to initialize container pool: %v", err)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		t.Fatal("container pool is closed")
	}
	p.mu.Unlock()

	t.Log("Acquiring container from pool...")
	container := <-p.containers
	t.Logf("Acquired container at %s:%d", container.Host, container.Port)

	cleanupContainer(container)

	t.Cleanup(func() {
		cleanupContainer(container)

		p.mu.Lock()
		defer p.mu.Unlock()

		if !p.closed {
			p.containers <- container
			t.Log("Released container back to pool")
		}
	})

	return container
}

// Close terminates all containers in the pool.
func (p *ContainerPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	close(p.containers)

	ctx := context.Background()
	for _, c := range p.allContainers {
		if c != nil && c.Container != nil {
			_ = c.Container.Terminate(ctx)
		}
	}
}

// Size returns the pool size.
func (p *ContainerPool) Size() int {
	return p.size
}

// cleanupContainer removes test files and stops any running compose stacks.
func cleanupContainer(c *SSHDockerContainer) {
	commands := []string{
		"rm -rf /tmp/test-* 2>/dev/null || true",
		"rm -rf /opt/stacks 2>/dev/null || true",
		"docker compose ls -q 2>/dev/null | xargs -r docker compose rm -fsv 2>/dev/null || true",
	}

	for _, cmd := range commands {
		_, _ = c.runCommand(cmd)
	}
}

// createPoolContainer creates a single container for the pool.
func createPoolContainer(t *testing.T, index int) (*SSHDockerContainer, error) {
	ctx := context.Background()

	privateKey, publicKey, err := generateSSHKeyPairForPool()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Use custom Dockerfile with SSH and Docker CLI
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
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "22/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	sshContainer := &SSHDockerContainer{
		Container:      container,
		Host:           host,
		Port:           mappedPort.Int(),
		User:           "testuser",
		PrivateKey:     privateKey,
		PrivateKeyPath: keyPath,
	}

	if err := waitForSSHReady(sshContainer, 30*time.Second); err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("SSH not ready: %w", err)
	}

	t.Logf("Created pool container %d at %s:%d", index, host, mappedPort.Int())
	return sshContainer, nil
}

// setupSSHInContainer installs and configures SSH server inside the container.
func setupSSHInContainer(ctx context.Context, container testcontainers.Container, publicKey string) error {
	commands := []string{
		// Install openssh
		"apk add --no-cache openssh",
		// Generate host keys
		"ssh-keygen -A",
		// Configure SSH
		"mkdir -p /root/.ssh",
		fmt.Sprintf("echo '%s' > /root/.ssh/authorized_keys", publicKey),
		"chmod 700 /root/.ssh",
		"chmod 600 /root/.ssh/authorized_keys",
		// Configure sshd
		"sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config",
		"sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
		"sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
		// Start SSH daemon
		"/usr/sbin/sshd",
	}

	for _, cmd := range commands {
		exitCode, _, err := container.Exec(ctx, []string{"sh", "-c", cmd})
		if err != nil {
			return fmt.Errorf("exec failed for '%s': %w", cmd, err)
		}
		if exitCode != 0 {
			return fmt.Errorf("command '%s' failed with exit code %d", cmd, exitCode)
		}
	}

	return nil
}

// generateSSHKeyPairForPool generates an SSH key pair.
func generateSSHKeyPairForPool() (privateKeyPEM, publicKeySSH string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH public key: %w", err)
	}
	publicKeySSH = string(ssh.MarshalAuthorizedKey(publicKey))

	return privateKeyPEM, publicKeySSH, nil
}

// waitForSSHReady waits for SSH to be ready.
func waitForSSHReady(c *SSHDockerContainer, timeout time.Duration) error {
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
