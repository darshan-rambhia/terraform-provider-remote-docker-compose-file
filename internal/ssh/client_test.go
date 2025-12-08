package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandPath(t *testing.T) {
	t.Parallel()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home directory: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "path with tilde",
			input:    "~/test/path",
			expected: filepath.Join(homeDir, "test/path"),
		},
		{
			name:     "absolute path",
			input:    "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "relative path",
			input:    "relative/path",
			expected: "relative/path",
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "tilde only",
			input:    "~",
			expected: "~",
		},
		{
			name:     "tilde with slash only",
			input:    "~/",
			expected: homeDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ExpandPath(tt.input)
			if result != tt.expected {
				t.Errorf("ExpandPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "'hello'",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "'hello world'",
		},
		{
			name:     "string with single quote",
			input:    "it's",
			expected: "'it'\"'\"'s'",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "string with special chars",
			input:    "hello; rm -rf /",
			expected: "'hello; rm -rf /'",
		},
		{
			name:     "string with multiple single quotes",
			input:    "it's a 'test'",
			expected: "'it'\"'\"'s a '\"'\"'test'\"'\"''",
		},
		{
			name:     "path with spaces",
			input:    "/opt/my folder/docker-compose.yaml",
			expected: "'/opt/my folder/docker-compose.yaml'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ShellQuote(tt.input)
			if result != tt.expected {
				t.Errorf("ShellQuote(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "valid 3-digit mode", mode: "644", wantErr: false},
		{name: "valid 4-digit mode", mode: "0755", wantErr: false},
		{name: "valid 3-digit executable", mode: "755", wantErr: false},
		{name: "valid 4-digit full perms", mode: "0777", wantErr: false},
		{name: "empty mode", mode: "", wantErr: false},
		{name: "invalid - contains 8", mode: "648", wantErr: true},
		{name: "invalid - contains 9", mode: "794", wantErr: true},
		{name: "invalid - too short", mode: "64", wantErr: true},
		{name: "invalid - too long", mode: "06440", wantErr: true},
		{name: "invalid - letters", mode: "abc", wantErr: true},
		{name: "invalid - mixed", mode: "64a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestValidateOwnerGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     string
		fieldName string
		wantErr   bool
	}{
		{name: "valid username", value: "root", fieldName: "owner", wantErr: false},
		{name: "valid group", value: "www-data", fieldName: "group", wantErr: false},
		{name: "numeric uid", value: "1000", fieldName: "owner", wantErr: false},
		{name: "numeric gid", value: "100", fieldName: "group", wantErr: false},
		{name: "underscore prefix", value: "_apt", fieldName: "owner", wantErr: false},
		{name: "underscore in name", value: "some_user", fieldName: "owner", wantErr: false},
		{name: "empty value", value: "", fieldName: "owner", wantErr: false},
		{name: "too long", value: "this_is_a_very_long_username_that_exceeds_32_chars", fieldName: "owner", wantErr: true},
		{name: "invalid chars", value: "user@domain", fieldName: "owner", wantErr: true},
		{name: "starts with hyphen", value: "-user", fieldName: "owner", wantErr: true},
		{name: "starts with number", value: "1user", fieldName: "owner", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateOwnerGroup(tt.value, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOwnerGroup(%q, %q) error = %v, wantErr %v", tt.value, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "text content",
			content:  []byte("Hello, World!\nThis is text."),
			expected: false,
		},
		{
			name:     "binary content with null byte",
			content:  []byte{0x48, 0x65, 0x6c, 0x00, 0x6c, 0x6f},
			expected: true,
		},
		{
			name:     "empty content",
			content:  []byte{},
			expected: false,
		},
		{
			name:     "yaml content",
			content:  []byte("version: '3.8'\nservices:\n  web:\n    image: nginx"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsBinaryContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsBinaryContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestInferAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   Config
		expected AuthMethod
	}{
		{
			name:     "password auth",
			config:   Config{Password: "secret"},
			expected: AuthMethodPassword,
		},
		{
			name:     "certificate auth with content",
			config:   Config{Certificate: "cert-content"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "certificate auth with path",
			config:   Config{CertificatePath: "/path/to/cert"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "default to private key",
			config:   Config{},
			expected: AuthMethodPrivateKey,
		},
		{
			name:     "private key with key path",
			config:   Config{KeyPath: "~/.ssh/id_rsa"},
			expected: AuthMethodPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := inferAuthMethod(tt.config)
			if result != tt.expected {
				t.Errorf("inferAuthMethod() = %v, want %v", result, tt.expected)
			}
		})
	}
}
