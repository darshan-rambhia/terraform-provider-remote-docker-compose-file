package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestStackResource_Metadata(t *testing.T) {
	t.Parallel()

	r := NewStackResource()
	req := resource.MetadataRequest{ProviderTypeName: "docker_compose"}
	resp := &resource.MetadataResponse{}

	r.Metadata(context.Background(), req, resp)

	if resp.TypeName != "docker_compose_stack" {
		t.Errorf("Metadata() TypeName = %q, want %q", resp.TypeName, "docker_compose_stack")
	}
}

func TestStackResource_Schema(t *testing.T) {
	t.Parallel()

	r := NewStackResource()
	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned errors: %v", resp.Diagnostics)
	}

	// Verify required attributes exist
	requiredAttrs := []string{"host", "remote_path", "content"}
	for _, attr := range requiredAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("Schema() missing required attribute %q", attr)
		}
	}

	// Verify optional attributes exist
	optionalAttrs := []string{"ssh_user", "ssh_key_path", "ssh_port", "up", "validate", "bastion_host"}
	for _, attr := range optionalAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("Schema() missing optional attribute %q", attr)
		}
	}

	// Verify computed attributes exist
	computedAttrs := []string{"id", "content_hash"}
	for _, attr := range computedAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("Schema() missing computed attribute %q", attr)
		}
	}
}

func TestHashContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "simple content",
			content: "version: '3.8'",
		},
		{
			name:    "empty content",
			content: "",
		},
		{
			name: "multiline content",
			content: `version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hash := hashContent(tt.content)

			// Verify hash format
			if len(hash) < 10 || hash[:7] != "sha256:" {
				t.Errorf("hashContent() = %q, expected sha256: prefix", hash)
			}

			// Verify determinism
			hash2 := hashContent(tt.content)
			if hash != hash2 {
				t.Errorf("hashContent() not deterministic: %q != %q", hash, hash2)
			}
		})
	}
}

func TestHashContent_Uniqueness(t *testing.T) {
	t.Parallel()

	content1 := "version: '3.8'"
	content2 := "version: '3.9'"

	hash1 := hashContent(content1)
	hash2 := hashContent(content2)

	if hash1 == hash2 {
		t.Error("hashContent() should produce different hashes for different content")
	}
}

func TestStackResource_GetSSHConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		data            *StackResourceModel
		providerConfig  *DockerComposeProviderModel
		wantHost        string
		wantUser        string
		wantPort        int
		wantPassword    string
		wantBastionHost string
		wantBastionPort int
		wantBastionUser string
		wantInsecure    bool
		wantCert        string
		wantCertPath    string
	}{
		// Basic config tests
		{
			name: "basic config from resource",
			data: &StackResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHUser: types.StringValue("deploy"),
				SSHPort: types.Int64Value(22),
			},
			wantHost: "192.168.1.100",
			wantUser: "deploy",
			wantPort: 22,
		},
		{
			name: "password auth",
			data: &StackResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHUser:     types.StringValue("root"),
				SSHPort:     types.Int64Value(22),
				SSHPassword: types.StringValue("secret"),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "root",
			wantPort:     22,
			wantPassword: "secret",
		},
		{
			name: "custom port",
			data: &StackResourceModel{
				Host:    types.StringValue("example.com"),
				SSHUser: types.StringValue("admin"),
				SSHPort: types.Int64Value(2222),
			},
			wantHost: "example.com",
			wantUser: "admin",
			wantPort: 2222,
		},
		{
			name: "fallback to provider config",
			data: &StackResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHUser:     types.StringValue(""),
				SSHPort:     types.Int64Value(22),
				SSHPassword: types.StringNull(),
			},
			providerConfig: &DockerComposeProviderModel{
				SSHUser:     types.StringValue("provider-user"),
				SSHPassword: types.StringValue("provider-pass"),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "",
			wantPort:     22,
			wantPassword: "provider-pass",
		},
		// Bastion tests
		{
			name: "bastion from resource",
			data: &StackResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHUser:     types.StringValue("root"),
				SSHPort:     types.Int64Value(22),
				BastionHost: types.StringValue("bastion.example.com"),
				BastionPort: types.Int64Value(2222),
				BastionUser: types.StringValue("jump-user"),
			},
			wantHost:        "192.168.1.100",
			wantUser:        "root",
			wantPort:        22,
			wantBastionHost: "bastion.example.com",
			wantBastionPort: 2222,
			wantBastionUser: "jump-user",
		},
		{
			name: "bastion from provider",
			data: &StackResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHUser:     types.StringValue("root"),
				SSHPort:     types.Int64Value(22),
				BastionHost: types.StringNull(),
			},
			providerConfig: &DockerComposeProviderModel{
				BastionHost: types.StringValue("provider-bastion.example.com"),
				BastionPort: types.Int64Value(22),
				BastionUser: types.StringValue("provider-jump"),
			},
			wantHost:        "192.168.1.100",
			wantUser:        "root",
			wantPort:        22,
			wantBastionHost: "provider-bastion.example.com",
			wantBastionPort: 22,
			wantBastionUser: "provider-jump",
		},
		{
			name: "no bastion",
			data: &StackResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHUser:     types.StringValue("root"),
				SSHPort:     types.Int64Value(22),
				BastionHost: types.StringNull(),
			},
			wantHost:        "192.168.1.100",
			wantUser:        "root",
			wantPort:        22,
			wantBastionHost: "",
			wantBastionPort: 0,
			wantBastionUser: "",
		},
		// InsecureIgnoreHostKey tests
		{
			name: "insecure from resource",
			data: &StackResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHUser:               types.StringValue("root"),
				SSHPort:               types.Int64Value(22),
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "root",
			wantPort:     22,
			wantInsecure: true,
		},
		{
			name: "insecure from provider",
			data: &StackResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHUser:               types.StringValue("root"),
				SSHPort:               types.Int64Value(22),
				InsecureIgnoreHostKey: types.BoolNull(),
			},
			providerConfig: &DockerComposeProviderModel{
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "root",
			wantPort:     22,
			wantInsecure: true,
		},
		{
			name: "secure by default",
			data: &StackResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHUser:               types.StringValue("root"),
				SSHPort:               types.Int64Value(22),
				InsecureIgnoreHostKey: types.BoolNull(),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "root",
			wantPort:     22,
			wantInsecure: false,
		},
		// Certificate tests
		{
			name: "certificate from resource",
			data: &StackResourceModel{
				Host:           types.StringValue("192.168.1.100"),
				SSHUser:        types.StringValue("root"),
				SSHPort:        types.Int64Value(22),
				SSHCertificate: types.StringValue("cert-content"),
			},
			wantHost: "192.168.1.100",
			wantUser: "root",
			wantPort: 22,
			wantCert: "cert-content",
		},
		{
			name: "certificate path from resource",
			data: &StackResourceModel{
				Host:               types.StringValue("192.168.1.100"),
				SSHUser:            types.StringValue("root"),
				SSHPort:            types.Int64Value(22),
				SSHCertificatePath: types.StringValue("/path/to/cert"),
			},
			wantHost:     "192.168.1.100",
			wantUser:     "root",
			wantPort:     22,
			wantCertPath: "/path/to/cert",
		},
		{
			name: "certificate from provider",
			data: &StackResourceModel{
				Host:           types.StringValue("192.168.1.100"),
				SSHUser:        types.StringValue("root"),
				SSHPort:        types.Int64Value(22),
				SSHCertificate: types.StringNull(),
			},
			providerConfig: &DockerComposeProviderModel{
				SSHCertificate: types.StringValue("provider-cert"),
			},
			wantHost: "192.168.1.100",
			wantUser: "root",
			wantPort: 22,
			wantCert: "provider-cert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &StackResource{
				providerConfig: tt.providerConfig,
			}

			config := r.getSSHConfig(tt.data)

			if config.Host != tt.wantHost {
				t.Errorf("getSSHConfig() Host = %q, want %q", config.Host, tt.wantHost)
			}
			if config.User != tt.wantUser {
				t.Errorf("getSSHConfig() User = %q, want %q", config.User, tt.wantUser)
			}
			if config.Port != tt.wantPort {
				t.Errorf("getSSHConfig() Port = %d, want %d", config.Port, tt.wantPort)
			}
			if config.Password != tt.wantPassword {
				t.Errorf("getSSHConfig() Password = %q, want %q", config.Password, tt.wantPassword)
			}
			if config.BastionHost != tt.wantBastionHost {
				t.Errorf("getSSHConfig() BastionHost = %q, want %q", config.BastionHost, tt.wantBastionHost)
			}
			if config.BastionPort != tt.wantBastionPort {
				t.Errorf("getSSHConfig() BastionPort = %d, want %d", config.BastionPort, tt.wantBastionPort)
			}
			if config.BastionUser != tt.wantBastionUser {
				t.Errorf("getSSHConfig() BastionUser = %q, want %q", config.BastionUser, tt.wantBastionUser)
			}
			if config.InsecureIgnoreHostKey != tt.wantInsecure {
				t.Errorf("getSSHConfig() InsecureIgnoreHostKey = %v, want %v", config.InsecureIgnoreHostKey, tt.wantInsecure)
			}
			if config.Certificate != tt.wantCert {
				t.Errorf("getSSHConfig() Certificate = %q, want %q", config.Certificate, tt.wantCert)
			}
			if config.CertificatePath != tt.wantCertPath {
				t.Errorf("getSSHConfig() CertificatePath = %q, want %q", config.CertificatePath, tt.wantCertPath)
			}
		})
	}
}

func TestStackResource_ValidateComposeFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		remotePath   string
		cmdResult    CommandResult
		wantErr      bool
		wantDirPart  string
		wantFilePart string
	}{
		{
			name:         "valid compose file",
			remotePath:   "/opt/stacks/app/docker-compose.yaml",
			cmdResult:    CommandResult{Stdout: "", Stderr: "", Err: nil},
			wantErr:      false,
			wantDirPart:  "cd '/opt/stacks/app'",
			wantFilePart: "-f 'docker-compose.yaml'",
		},
		{
			name:       "invalid compose file",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult: CommandResult{
				Stderr: "service 'web' has neither an image nor a build context",
				Err:    errors.New("exit status 1"),
			},
			wantErr:      true,
			wantDirPart:  "cd '/opt/stacks/app'",
			wantFilePart: "-f 'docker-compose.yaml'",
		},
		{
			name:       "docker not installed",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult: CommandResult{
				Stderr: "docker: command not found",
				Err:    errors.New("exit status 127"),
			},
			wantErr:      true,
			wantDirPart:  "cd '/opt/stacks/app'",
			wantFilePart: "-f 'docker-compose.yaml'",
		},
		{
			name:         "path with spaces",
			remotePath:   "/opt/my stacks/app/docker-compose.yaml",
			cmdResult:    CommandResult{Stdout: "", Stderr: "", Err: nil},
			wantErr:      false,
			wantDirPart:  "cd '/opt/my stacks/app'",
			wantFilePart: "-f 'docker-compose.yaml'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			mock.SetCommandOutput("docker compose", tt.cmdResult.Stdout, tt.cmdResult.Stderr, tt.cmdResult.Err)

			r := &StackResource{}
			err := r.validateComposeFile(context.Background(), mock, tt.remotePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateComposeFile() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify command was executed and has correct format
			commands := mock.GetCommands()
			if len(commands) < 1 {
				t.Error("validateComposeFile() did not execute docker compose command")
			} else {
				cmd := commands[0]
				if !containsString(cmd, tt.wantDirPart) {
					t.Errorf("Command %q missing expected dir part %q", cmd, tt.wantDirPart)
				}
				if !containsString(cmd, tt.wantFilePart) {
					t.Errorf("Command %q missing expected file part %q", cmd, tt.wantFilePart)
				}
				if !containsString(cmd, "config --quiet") {
					t.Errorf("Command %q missing 'config --quiet'", cmd)
				}
			}
		})
	}
}

func TestStackResource_ComposeUp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		remotePath         string
		cmdResult          CommandResult
		wantErr            bool
		checkShellEscaping bool
	}{
		{
			name:       "successful up",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult:  CommandResult{Stdout: "Creating network...\nCreating container...", Err: nil},
			wantErr:    false,
		},
		{
			name:       "up failure",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult: CommandResult{
				Stderr: "Error response from daemon: pull access denied",
				Err:    errors.New("exit status 1"),
			},
			wantErr: true,
		},
		{
			name:               "shell escaping with single quote",
			remotePath:         "/opt/stack's/docker-compose.yaml",
			cmdResult:          CommandResult{Stdout: "", Err: nil},
			wantErr:            false,
			checkShellEscaping: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			mock.SetCommandOutput("up -d", tt.cmdResult.Stdout, tt.cmdResult.Stderr, tt.cmdResult.Err)

			r := &StackResource{}
			err := r.composeUp(context.Background(), mock, tt.remotePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("composeUp() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !mock.CommandWasExecuted("up -d") {
				t.Error("composeUp() did not execute 'docker compose up -d' command")
			}

			// Verify shell escaping if needed
			if tt.checkShellEscaping {
				commands := mock.GetCommands()
				if len(commands) > 0 {
					cmd := commands[0]
					if containsString(cmd, "stack's") {
						t.Errorf("Command %q contains unescaped single quote", cmd)
					}
				}
			}
		})
	}
}

func TestStackResource_ComposeDown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remotePath string
		cmdResult  CommandResult
		wantErr    bool
	}{
		{
			name:       "successful down",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult:  CommandResult{Stdout: "Stopping container...\nRemoving network...", Err: nil},
			wantErr:    false,
		},
		{
			name:       "down with no running containers",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult:  CommandResult{Stdout: "", Stderr: "", Err: nil},
			wantErr:    false,
		},
		{
			name:       "down failure",
			remotePath: "/opt/stacks/app/docker-compose.yaml",
			cmdResult: CommandResult{
				Stderr: "Error: No such container",
				Err:    errors.New("exit status 1"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			mock.SetCommandOutput("down", tt.cmdResult.Stdout, tt.cmdResult.Stderr, tt.cmdResult.Err)

			r := &StackResource{}
			err := r.composeDown(context.Background(), mock, tt.remotePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("composeDown() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !mock.CommandWasExecuted("down") {
				t.Error("composeDown() did not execute 'docker compose down' command")
			}
		})
	}
}

func TestStackResource_CreateSSHClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		data       *StackResourceModel
		factoryErr error
		wantErr    bool
	}{
		{
			name: "successful client creation",
			data: &StackResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHUser: types.StringValue("root"),
				SSHPort: types.Int64Value(22),
			},
			wantErr: false,
		},
		{
			name: "factory error",
			data: &StackResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHUser: types.StringValue("root"),
				SSHPort: types.Int64Value(22),
			},
			factoryErr: ErrMockSSHConnection,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var factory SSHClientFactory
			if tt.factoryErr != nil {
				factory = NewMockSSHClientFactoryWithError(tt.factoryErr)
			} else {
				factory = NewMockSSHClientFactory(NewMockSSHClient())
			}

			r := &StackResource{
				sshClientFactory: factory,
			}

			client, err := r.createSSHClient(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("createSSHClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && client == nil {
				t.Error("createSSHClient() returned nil client without error")
			}
		})
	}
}

func TestStackResource_Configure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		providerData interface{}
		wantErr      bool
	}{
		{
			name:         "valid provider data",
			providerData: &DockerComposeProviderModel{},
			wantErr:      false,
		},
		{
			name:         "nil provider data",
			providerData: nil,
			wantErr:      false,
		},
		{
			name:         "wrong type",
			providerData: "invalid",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &StackResource{}
			req := resource.ConfigureRequest{
				ProviderData: tt.providerData,
			}
			resp := &resource.ConfigureResponse{}

			r.Configure(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Configure() hasError = %v, wantErr %v", resp.Diagnostics.HasError(), tt.wantErr)
			}
		})
	}
}

func TestStackResource_ImportState_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		importID       string
		wantHost       string
		wantRemotePath string
		wantErr        bool
	}{
		{
			name:           "valid import ID",
			importID:       "192.168.1.100:/opt/stacks/app/docker-compose.yaml",
			wantHost:       "192.168.1.100",
			wantRemotePath: "/opt/stacks/app/docker-compose.yaml",
			wantErr:        false,
		},
		{
			name:           "hostname with domain",
			importID:       "server.example.com:/opt/compose.yaml",
			wantHost:       "server.example.com",
			wantRemotePath: "/opt/compose.yaml",
			wantErr:        false,
		},
		{
			name:     "invalid - no colon",
			importID: "192.168.1.100/opt/compose.yaml",
			wantErr:  true,
		},
		{
			name:     "invalid - empty host",
			importID: ":/opt/compose.yaml",
			wantErr:  true,
		},
		{
			name:     "invalid - empty path",
			importID: "192.168.1.100:",
			wantErr:  true,
		},
		{
			name:     "invalid - relative path",
			importID: "192.168.1.100:opt/compose.yaml",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &StackResource{}

			// Create a mock state schema
			schemaReq := resource.SchemaRequest{}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), schemaReq, schemaResp)

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
			}

			req := resource.ImportStateRequest{
				ID: tt.importID,
			}
			resp := &resource.ImportStateResponse{
				State: state,
			}

			r.ImportState(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("ImportState() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}
		})
	}
}

func TestStackResource_Create(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		setupMock         func(*MockSSHClient)
		factoryErr        error
		up                bool
		validate          bool
		wantErr           bool
		wantUploadCalled  bool
		wantComposeCalled bool
	}{
		{
			name:              "successful create without up or validate",
			setupMock:         func(m *MockSSHClient) {},
			up:                false,
			validate:          false,
			wantErr:           false,
			wantUploadCalled:  true,
			wantComposeCalled: false,
		},
		{
			name:              "successful create with validate",
			setupMock:         func(m *MockSSHClient) {},
			up:                false,
			validate:          true,
			wantErr:           false,
			wantUploadCalled:  true,
			wantComposeCalled: true,
		},
		{
			name:              "successful create with up",
			setupMock:         func(m *MockSSHClient) {},
			up:                true,
			validate:          false,
			wantErr:           false,
			wantUploadCalled:  true,
			wantComposeCalled: true,
		},
		{
			name: "upload fails",
			setupMock: func(m *MockSSHClient) {
				m.UploadContentError = ErrMockUpload
			},
			up:               false,
			validate:         false,
			wantErr:          true,
			wantUploadCalled: true,
		},
		{
			name: "validation fails",
			setupMock: func(m *MockSSHClient) {
				m.SetCommandOutput("config --quiet", "", "invalid compose file", errors.New("validation failed"))
			},
			up:               false,
			validate:         true,
			wantErr:          true,
			wantUploadCalled: true,
		},
		{
			name: "compose up fails",
			setupMock: func(m *MockSSHClient) {
				m.SetCommandOutput("up -d", "", "docker daemon error", errors.New("compose up failed"))
			},
			up:               true,
			validate:         false,
			wantErr:          true,
			wantUploadCalled: true,
		},
		{
			name:       "SSH connection fails",
			setupMock:  func(m *MockSSHClient) {},
			factoryErr: ErrMockSSHConnection,
			up:         false,
			validate:   false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			tt.setupMock(mock)

			var factory SSHClientFactory
			if tt.factoryErr != nil {
				factory = NewMockSSHClientFactoryWithError(tt.factoryErr)
			} else {
				factory = NewMockSSHClientFactory(mock)
			}

			r := &StackResource{
				sshClientFactory: factory,
			}

			// Build the plan schema
			schemaReq := resource.SchemaRequest{}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), schemaReq, schemaResp)

			// Create plan data
			planValue := tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
				"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
				"remote_path":              tftypes.NewValue(tftypes.String, "/opt/stacks/test/docker-compose.yaml"),
				"content":                  tftypes.NewValue(tftypes.String, "version: '3.8'\nservices:\n  test:\n    image: alpine"),
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, nil),
				"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
				"bastion_user":             tftypes.NewValue(tftypes.String, nil),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
				"up":                       tftypes.NewValue(tftypes.Bool, tt.up),
				"validate":                 tftypes.NewValue(tftypes.Bool, tt.validate),
				"content_hash":             tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
			})

			plan := tfsdk.Plan{
				Schema: schemaResp.Schema,
				Raw:    planValue,
			}

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
			}

			req := resource.CreateRequest{
				Plan: plan,
			}
			resp := &resource.CreateResponse{
				State: state,
			}

			r.Create(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Create() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}

			if tt.wantUploadCalled {
				if _, uploaded := mock.GetUploadedContent("/opt/stacks/test/docker-compose.yaml"); !uploaded && !tt.wantErr {
					t.Error("Create() should have uploaded content")
				}
			}

			if tt.wantComposeCalled && !tt.wantErr {
				hasComposeCmd := mock.CommandWasExecuted("docker compose")
				if !hasComposeCmd {
					t.Error("Create() should have executed docker compose command")
				}
			}
		})
	}
}

func TestStackResource_Read(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setupMock   func(*MockSSHClient)
		factoryErr  error
		wantErr     bool
		wantRemoved bool
	}{
		{
			name: "file exists",
			setupMock: func(m *MockSSHClient) {
				m.AddFile("/opt/stacks/test/docker-compose.yaml", []byte("version: '3.8'"))
			},
			wantErr:     false,
			wantRemoved: false,
		},
		{
			name: "file does not exist - resource removed",
			setupMock: func(m *MockSSHClient) {
				// Don't add the file
			},
			wantErr:     false,
			wantRemoved: true,
		},
		{
			name: "error checking file existence",
			setupMock: func(m *MockSSHClient) {
				m.FileExistsError = errors.New("SSH error")
			},
			wantErr:     true,
			wantRemoved: false,
		},
		{
			name: "error getting file hash",
			setupMock: func(m *MockSSHClient) {
				m.AddFile("/opt/stacks/test/docker-compose.yaml", []byte("version: '3.8'"))
				m.GetFileHashError = errors.New("hash error")
			},
			wantErr:     true,
			wantRemoved: false,
		},
		{
			name:       "SSH connection fails",
			setupMock:  func(m *MockSSHClient) {},
			factoryErr: ErrMockSSHConnection,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			tt.setupMock(mock)

			var factory SSHClientFactory
			if tt.factoryErr != nil {
				factory = NewMockSSHClientFactoryWithError(tt.factoryErr)
			} else {
				factory = NewMockSSHClientFactory(mock)
			}

			r := &StackResource{
				sshClientFactory: factory,
			}

			schemaReq := resource.SchemaRequest{}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), schemaReq, schemaResp)

			stateValue := tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, "192.168.1.100:/opt/stacks/test/docker-compose.yaml"),
				"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
				"remote_path":              tftypes.NewValue(tftypes.String, "/opt/stacks/test/docker-compose.yaml"),
				"content":                  tftypes.NewValue(tftypes.String, "version: '3.8'"),
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, nil),
				"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
				"bastion_user":             tftypes.NewValue(tftypes.String, nil),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
				"up":                       tftypes.NewValue(tftypes.Bool, false),
				"validate":                 tftypes.NewValue(tftypes.Bool, true),
				"content_hash":             tftypes.NewValue(tftypes.String, "sha256:abc123"),
			})

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    stateValue,
			}

			req := resource.ReadRequest{
				State: state,
			}
			resp := &resource.ReadResponse{
				State: state,
			}

			r.Read(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Read() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}

			if tt.wantRemoved && !resp.State.Raw.IsNull() {
				t.Error("Read() should have removed resource from state")
			}
		})
	}
}

func TestStackResource_Update(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setupMock   func(*MockSSHClient)
		factoryErr  error
		up          bool
		validate    bool
		wantErr     bool
		wantDownCmd bool
	}{
		{
			name:        "update without up",
			setupMock:   func(m *MockSSHClient) {},
			up:          false,
			validate:    false,
			wantErr:     false,
			wantDownCmd: false,
		},
		{
			name:        "update with up runs down first",
			setupMock:   func(m *MockSSHClient) {},
			up:          true,
			validate:    false,
			wantErr:     false,
			wantDownCmd: true,
		},
		{
			name: "upload fails",
			setupMock: func(m *MockSSHClient) {
				m.UploadContentError = ErrMockUpload
			},
			up:      false,
			wantErr: true,
		},
		{
			name: "validation fails",
			setupMock: func(m *MockSSHClient) {
				m.SetCommandOutput("config --quiet", "", "invalid", errors.New("failed"))
			},
			validate: true,
			wantErr:  true,
		},
		{
			name:       "SSH connection fails",
			setupMock:  func(m *MockSSHClient) {},
			factoryErr: ErrMockSSHConnection,
			up:         false,
			validate:   false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			tt.setupMock(mock)

			var factory SSHClientFactory
			if tt.factoryErr != nil {
				factory = NewMockSSHClientFactoryWithError(tt.factoryErr)
			} else {
				factory = NewMockSSHClientFactory(mock)
			}

			r := &StackResource{
				sshClientFactory: factory,
			}

			schemaReq := resource.SchemaRequest{}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), schemaReq, schemaResp)

			values := map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, "192.168.1.100:/opt/stacks/test/docker-compose.yaml"),
				"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
				"remote_path":              tftypes.NewValue(tftypes.String, "/opt/stacks/test/docker-compose.yaml"),
				"content":                  tftypes.NewValue(tftypes.String, "version: '3.8'\nservices:\n  updated:\n    image: nginx"),
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, nil),
				"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
				"bastion_user":             tftypes.NewValue(tftypes.String, nil),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
				"up":                       tftypes.NewValue(tftypes.Bool, tt.up),
				"validate":                 tftypes.NewValue(tftypes.Bool, tt.validate),
				"content_hash":             tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
			}

			planValue := tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), values)
			stateValue := tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, "192.168.1.100:/opt/stacks/test/docker-compose.yaml"),
				"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
				"remote_path":              tftypes.NewValue(tftypes.String, "/opt/stacks/test/docker-compose.yaml"),
				"content":                  tftypes.NewValue(tftypes.String, "version: '3.8'"),
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, nil),
				"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
				"bastion_user":             tftypes.NewValue(tftypes.String, nil),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
				"up":                       tftypes.NewValue(tftypes.Bool, tt.up),
				"validate":                 tftypes.NewValue(tftypes.Bool, tt.validate),
				"content_hash":             tftypes.NewValue(tftypes.String, "sha256:old"),
			})

			plan := tfsdk.Plan{
				Schema: schemaResp.Schema,
				Raw:    planValue,
			}
			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    stateValue,
			}

			req := resource.UpdateRequest{
				Plan:  plan,
				State: state,
			}
			resp := &resource.UpdateResponse{
				State: state,
			}

			r.Update(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Update() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}

			if tt.wantDownCmd && !tt.wantErr {
				if !mock.CommandWasExecuted("down") {
					t.Error("Update() should have executed 'docker compose down'")
				}
			}
		})
	}
}

func TestStackResource_Delete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		setupMock        func(*MockSSHClient)
		factoryErr       error
		wantErr          bool
		wantDownCalled   bool
		wantDeleteCalled bool
	}{
		{
			name:             "successful delete",
			setupMock:        func(m *MockSSHClient) {},
			wantErr:          false,
			wantDownCalled:   true,
			wantDeleteCalled: true,
		},
		{
			name: "delete file fails",
			setupMock: func(m *MockSSHClient) {
				m.DeleteFileError = ErrMockDelete
			},
			wantErr:          true,
			wantDownCalled:   true,
			wantDeleteCalled: true,
		},
		{
			name: "compose down fails but delete continues",
			setupMock: func(m *MockSSHClient) {
				m.SetCommandOutput("down", "", "no stack", errors.New("down failed"))
			},
			wantErr:          false, // down errors are ignored
			wantDownCalled:   true,
			wantDeleteCalled: true,
		},
		{
			name:             "SSH connection fails",
			setupMock:        func(m *MockSSHClient) {},
			factoryErr:       ErrMockSSHConnection,
			wantErr:          true,
			wantDownCalled:   false,
			wantDeleteCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := NewMockSSHClient()
			tt.setupMock(mock)

			var factory SSHClientFactory
			if tt.factoryErr != nil {
				factory = NewMockSSHClientFactoryWithError(tt.factoryErr)
			} else {
				factory = NewMockSSHClientFactory(mock)
			}

			r := &StackResource{
				sshClientFactory: factory,
			}

			schemaReq := resource.SchemaRequest{}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), schemaReq, schemaResp)

			stateValue := tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), map[string]tftypes.Value{
				"id":                       tftypes.NewValue(tftypes.String, "192.168.1.100:/opt/stacks/test/docker-compose.yaml"),
				"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
				"remote_path":              tftypes.NewValue(tftypes.String, "/opt/stacks/test/docker-compose.yaml"),
				"content":                  tftypes.NewValue(tftypes.String, "version: '3.8'"),
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, nil),
				"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
				"bastion_user":             tftypes.NewValue(tftypes.String, nil),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
				"up":                       tftypes.NewValue(tftypes.Bool, true),
				"validate":                 tftypes.NewValue(tftypes.Bool, true),
				"content_hash":             tftypes.NewValue(tftypes.String, "sha256:abc"),
			})

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    stateValue,
			}

			req := resource.DeleteRequest{
				State: state,
			}
			resp := &resource.DeleteResponse{}

			r.Delete(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Delete() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}

			if tt.wantDownCalled && !mock.CommandWasExecuted("down") {
				t.Error("Delete() should have executed 'docker compose down'")
			}
		})
	}
}

func TestContentHashPlanModifier_PlanModifyString(t *testing.T) {
	t.Parallel()

	modifier := contentHashPlanModifier{}

	// Get the schema
	r := &StackResource{}
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)

	tests := []struct {
		name          string
		content       string
		planIsNull    bool
		contentIsNull bool
		wantHashSet   bool
	}{
		{
			name:        "computes hash from content",
			content:     "version: '3.8'\nservices:\n  test:\n    image: alpine",
			wantHashSet: true,
		},
		{
			name:        "empty content still computes hash",
			content:     "",
			wantHashSet: true,
		},
		{
			name:        "null plan does not compute hash",
			planIsNull:  true,
			wantHashSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var planValue tftypes.Value
			if tt.planIsNull {
				planValue = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil)
			} else {
				planValue = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), map[string]tftypes.Value{
					"id":                       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
					"host":                     tftypes.NewValue(tftypes.String, "192.168.1.100"),
					"remote_path":              tftypes.NewValue(tftypes.String, "/opt/test.yaml"),
					"content":                  tftypes.NewValue(tftypes.String, tt.content),
					"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
					"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
					"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
					"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
					"ssh_password":             tftypes.NewValue(tftypes.String, nil),
					"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
					"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
					"bastion_host":             tftypes.NewValue(tftypes.String, nil),
					"bastion_port":             tftypes.NewValue(tftypes.Number, nil),
					"bastion_user":             tftypes.NewValue(tftypes.String, nil),
					"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
					"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
					"bastion_password":         tftypes.NewValue(tftypes.String, nil),
					"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, nil),
					"up":                       tftypes.NewValue(tftypes.Bool, false),
					"validate":                 tftypes.NewValue(tftypes.Bool, true),
					"content_hash":             tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
				})
			}

			plan := tfsdk.Plan{
				Schema: schemaResp.Schema,
				Raw:    planValue,
			}

			req := planmodifier.StringRequest{
				Plan: plan,
			}
			resp := &planmodifier.StringResponse{}

			modifier.PlanModifyString(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Errorf("PlanModifyString() returned errors: %v", resp.Diagnostics)
			}

			if tt.wantHashSet {
				if resp.PlanValue.IsNull() || resp.PlanValue.IsUnknown() {
					t.Error("PlanModifyString() should have set plan value")
				}
				hash := resp.PlanValue.ValueString()
				if len(hash) < 10 || hash[:7] != "sha256:" {
					t.Errorf("PlanModifyString() hash = %q, expected sha256: prefix", hash)
				}
			}
		})
	}
}
