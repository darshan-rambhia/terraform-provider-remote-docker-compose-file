package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/darshan-rambhia/terraform-provider-docker-compose/internal/ssh"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &StackResource{}
var _ resource.ResourceWithImportState = &StackResource{}

func NewStackResource() resource.Resource {
	return &StackResource{
		sshClientFactory: DefaultSSHClientFactory,
	}
}

// SSHClientFactory is a function type that creates SSH clients.
type SSHClientFactory func(config ssh.Config) (ssh.ClientInterface, error)

// DefaultSSHClientFactory creates real SSH clients.
var DefaultSSHClientFactory SSHClientFactory = func(config ssh.Config) (ssh.ClientInterface, error) {
	return ssh.NewClient(config)
}

// StackResource defines the resource implementation.
type StackResource struct {
	providerConfig   *DockerComposeProviderModel
	sshClientFactory SSHClientFactory
}

// StackResourceModel describes the resource data model.
type StackResourceModel struct {
	// Required.
	Host       types.String `tfsdk:"host"`
	RemotePath types.String `tfsdk:"remote_path"`
	Content    types.String `tfsdk:"content"`

	// Optional - connection settings (override provider defaults).
	SSHUser            types.String `tfsdk:"ssh_user"`
	SSHPrivateKey      types.String `tfsdk:"ssh_private_key"`
	SSHKeyPath         types.String `tfsdk:"ssh_key_path"`
	SSHPort            types.Int64  `tfsdk:"ssh_port"`
	SSHPassword        types.String `tfsdk:"ssh_password"`
	SSHCertificate     types.String `tfsdk:"ssh_certificate"`
	SSHCertificatePath types.String `tfsdk:"ssh_certificate_path"`

	// Optional - bastion/jump host settings.
	BastionHost     types.String `tfsdk:"bastion_host"`
	BastionPort     types.Int64  `tfsdk:"bastion_port"`
	BastionUser     types.String `tfsdk:"bastion_user"`
	BastionKey      types.String `tfsdk:"bastion_private_key"`
	BastionKeyPath  types.String `tfsdk:"bastion_key_path"`
	BastionPassword types.String `tfsdk:"bastion_password"`

	// Optional - security settings.
	InsecureIgnoreHostKey types.Bool `tfsdk:"insecure_ignore_host_key"`

	// Optional - lifecycle settings.
	Up       types.Bool `tfsdk:"up"`
	Validate types.Bool `tfsdk:"validate"`

	// Computed.
	ID          types.String `tfsdk:"id"`
	ContentHash types.String `tfsdk:"content_hash"`
}

func (r *StackResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_stack"
}

func (r *StackResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
Manages a Docker Compose stack on a remote host via SSH.

## Behavior

- **Create**: Uploads compose file, optionally validates, optionally runs 'docker compose up -d'
- **Read**: Retrieves remote file hash for drift detection
- **Update**: If content changes, runs 'docker compose down' (if up=true), uploads new file, runs 'docker compose up -d'
- **Delete**: Runs 'docker compose down', removes compose file

## Important Notes

- Terraform tracks the **compose file**, not container state
- The 'up' flag is a convenience operation; containers may drift outside Terraform
- Remote host must have Docker and 'docker compose' (v2) installed

## Example Usage

` + "```hcl" + `
resource "remote_docker_compose_file_stack" "web" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/web/docker-compose.yaml"
  content     = file("${path.module}/docker-compose.yaml")
  up          = true
  validate    = true

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			// Required.
			"host": schema.StringAttribute{
				MarkdownDescription: "Remote host address (IP or hostname).",
				Required:            true,
			},
			"remote_path": schema.StringAttribute{
				MarkdownDescription: "Absolute path on the remote host where the compose file should be placed.",
				Required:            true,
			},
			"content": schema.StringAttribute{
				MarkdownDescription: "Content of the docker-compose file.",
				Required:            true,
			},

			// Optional - connection.
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "SSH user. Overrides provider default.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content. Mutually exclusive with ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file. Mutually exclusive with ssh_private_key.",
				Optional:            true,
			},
			"ssh_port": schema.Int64Attribute{
				MarkdownDescription: "SSH port. Defaults to 22.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(22),
			},
			"ssh_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for password authentication.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate": schema.StringAttribute{
				MarkdownDescription: "SSH certificate content for certificate authentication. Used with ssh_private_key or ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH certificate file for certificate authentication.",
				Optional:            true,
			},

			// Optional - bastion/jump host.
			"bastion_host": schema.StringAttribute{
				MarkdownDescription: "Bastion/jump host address for multi-hop SSH connections.",
				Optional:            true,
			},
			"bastion_port": schema.Int64Attribute{
				MarkdownDescription: "Bastion host SSH port. Defaults to 22.",
				Optional:            true,
			},
			"bastion_user": schema.StringAttribute{
				MarkdownDescription: "SSH user for bastion host. Falls back to ssh_user if not set.",
				Optional:            true,
			},
			"bastion_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content for bastion host (sensitive). Falls back to ssh_private_key if not set.",
				Optional:            true,
				Sensitive:           true,
			},
			"bastion_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file for bastion host. Falls back to ssh_key_path if not set.",
				Optional:            true,
			},
			"bastion_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for bastion host (sensitive).",
				Optional:            true,
				Sensitive:           true,
			},

			// Optional - security settings.
			"insecure_ignore_host_key": schema.BoolAttribute{
				MarkdownDescription: "Skip SSH host key verification. WARNING: Insecure. Defaults to false.",
				Optional:            true,
			},

			// Optional - lifecycle.
			"up": schema.BoolAttribute{
				MarkdownDescription: "Run 'docker compose up -d' after uploading. Defaults to false.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"validate": schema.BoolAttribute{
				MarkdownDescription: "Validate compose file with 'docker compose config' before applying. Defaults to true.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},

			// Computed.
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier (host:remote_path).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"content_hash": schema.StringAttribute{
				MarkdownDescription: "SHA256 hash of the compose file content.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					contentHashPlanModifier{},
				},
			},
		},
	}
}

func (r *StackResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*DockerComposeProviderModel)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *DockerComposeProviderModel, got: %T", req.ProviderData),
		)
		return
	}

	r.providerConfig = config
}

func (r *StackResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data StackResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Calculate content hash.
	hash := hashContent(data.Content.ValueString())

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Upload compose file.
	if err := client.UploadContent(ctx, []byte(data.Content.ValueString()), data.RemotePath.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to upload compose file", err.Error())
		return
	}

	// Validate compose file if requested.
	if data.Validate.ValueBool() {
		if err := r.validateComposeFile(ctx, client, data.RemotePath.ValueString()); err != nil {
			// Clean up the uploaded file on validation failure.
			_ = client.DeleteFile(ctx, data.RemotePath.ValueString())
			resp.Diagnostics.AddError("Compose file validation failed", err.Error())
			return
		}
	}

	// Run docker compose up if requested.
	if data.Up.ValueBool() {
		if err := r.composeUp(ctx, client, data.RemotePath.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to run 'docker compose up'", err.Error())
			return
		}
	}

	// Set computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.RemotePath.ValueString()))
	data.ContentHash = types.StringValue(hash)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *StackResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data StackResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Check if file exists.
	exists, err := client.FileExists(ctx, data.RemotePath.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to check remote file", err.Error())
		return
	}

	if !exists {
		// File was deleted externally - remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	// Get remote file hash to detect drift.
	remoteHash, err := client.GetFileHash(ctx, data.RemotePath.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to get remote file hash", err.Error())
		return
	}

	// Update content hash in state to reflect actual remote state.
	data.ContentHash = types.StringValue(remoteHash)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *StackResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data StackResourceModel
	var state StackResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Calculate new content hash.
	newHash := hashContent(data.Content.ValueString())

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// If up=true, run docker compose down before updating.
	if data.Up.ValueBool() {
		_ = r.composeDown(ctx, client, state.RemotePath.ValueString())
	}

	// Upload new compose file.
	if err := client.UploadContent(ctx, []byte(data.Content.ValueString()), data.RemotePath.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to upload compose file", err.Error())
		return
	}

	// Validate compose file if requested.
	if data.Validate.ValueBool() {
		if err := r.validateComposeFile(ctx, client, data.RemotePath.ValueString()); err != nil {
			resp.Diagnostics.AddError("Compose file validation failed", err.Error())
			return
		}
	}

	// Run docker compose up if requested.
	if data.Up.ValueBool() {
		if err := r.composeUp(ctx, client, data.RemotePath.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to run 'docker compose up'", err.Error())
			return
		}
	}

	// Update computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.RemotePath.ValueString()))
	data.ContentHash = types.StringValue(newHash)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *StackResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data StackResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Always run docker compose down (idempotent).
	_ = r.composeDown(ctx, client, data.RemotePath.ValueString())

	// Delete the compose file.
	if err := client.DeleteFile(ctx, data.RemotePath.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete compose file", err.Error())
		return
	}
}

func (r *StackResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	colonIdx := strings.Index(id, ":")
	if colonIdx == -1 || colonIdx == 0 || colonIdx == len(id)-1 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Import ID must be in format 'host:remote_path' (e.g., '192.168.1.100:/opt/stacks/app/docker-compose.yaml').\n"+
					"Got: %s", id,
			),
		)
		return
	}

	host := id[:colonIdx]
	remotePath := id[colonIdx+1:]

	if !strings.HasPrefix(remotePath, "/") {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Remote path must be an absolute path starting with '/'.\n"+
					"Got: %s", remotePath,
			),
		)
		return
	}

	if strings.Contains(remotePath, "..") {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Remote path must not contain directory traversal sequences (..).\n"+
					"Got: %s", remotePath,
			),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("remote_path"), remotePath)...)
}

// Helper functions.

// getSSHConfig builds an SSH config from resource data.
func (r *StackResource) getSSHConfig(data *StackResourceModel) ssh.Config {
	config := ssh.Config{
		Host: data.Host.ValueString(),
		Port: int(data.SSHPort.ValueInt64()),
		User: data.SSHUser.ValueString(),
	}

	// Determine SSH credentials - resource values override provider defaults.
	// Check password authentication.
	if !data.SSHPassword.IsNull() && data.SSHPassword.ValueString() != "" {
		config.Password = data.SSHPassword.ValueString()
	} else if r.providerConfig != nil && !r.providerConfig.SSHPassword.IsNull() {
		config.Password = r.providerConfig.SSHPassword.ValueString()
	}

	// Check private key authentication.
	if !data.SSHPrivateKey.IsNull() && data.SSHPrivateKey.ValueString() != "" {
		config.PrivateKey = data.SSHPrivateKey.ValueString()
	} else if !data.SSHKeyPath.IsNull() && data.SSHKeyPath.ValueString() != "" {
		config.KeyPath = data.SSHKeyPath.ValueString()
	} else if r.providerConfig != nil {
		if !r.providerConfig.SSHPrivateKey.IsNull() && r.providerConfig.SSHPrivateKey.ValueString() != "" {
			config.PrivateKey = r.providerConfig.SSHPrivateKey.ValueString()
		} else if !r.providerConfig.SSHKeyPath.IsNull() && r.providerConfig.SSHKeyPath.ValueString() != "" {
			config.KeyPath = r.providerConfig.SSHKeyPath.ValueString()
		}
	}

	// Check certificate authentication.
	if !data.SSHCertificate.IsNull() && data.SSHCertificate.ValueString() != "" {
		config.Certificate = data.SSHCertificate.ValueString()
	} else if !data.SSHCertificatePath.IsNull() && data.SSHCertificatePath.ValueString() != "" {
		config.CertificatePath = data.SSHCertificatePath.ValueString()
	} else if r.providerConfig != nil {
		if !r.providerConfig.SSHCertificate.IsNull() && r.providerConfig.SSHCertificate.ValueString() != "" {
			config.Certificate = r.providerConfig.SSHCertificate.ValueString()
		} else if !r.providerConfig.SSHCertificatePath.IsNull() && r.providerConfig.SSHCertificatePath.ValueString() != "" {
			config.CertificatePath = r.providerConfig.SSHCertificatePath.ValueString()
		}
	}

	// Check bastion/jump host configuration.
	if !data.BastionHost.IsNull() && data.BastionHost.ValueString() != "" {
		config.BastionHost = data.BastionHost.ValueString()
		if !data.BastionPort.IsNull() {
			config.BastionPort = int(data.BastionPort.ValueInt64())
		}
		if !data.BastionUser.IsNull() {
			config.BastionUser = data.BastionUser.ValueString()
		}
		if !data.BastionKey.IsNull() && data.BastionKey.ValueString() != "" {
			config.BastionKey = data.BastionKey.ValueString()
		} else if !data.BastionKeyPath.IsNull() && data.BastionKeyPath.ValueString() != "" {
			config.BastionKeyPath = data.BastionKeyPath.ValueString()
		}
		if !data.BastionPassword.IsNull() {
			config.BastionPassword = data.BastionPassword.ValueString()
		}
	} else if r.providerConfig != nil && !r.providerConfig.BastionHost.IsNull() && r.providerConfig.BastionHost.ValueString() != "" {
		config.BastionHost = r.providerConfig.BastionHost.ValueString()
		if !r.providerConfig.BastionPort.IsNull() {
			config.BastionPort = int(r.providerConfig.BastionPort.ValueInt64())
		}
		if !r.providerConfig.BastionUser.IsNull() {
			config.BastionUser = r.providerConfig.BastionUser.ValueString()
		}
		if !r.providerConfig.BastionKey.IsNull() && r.providerConfig.BastionKey.ValueString() != "" {
			config.BastionKey = r.providerConfig.BastionKey.ValueString()
		} else if !r.providerConfig.BastionKeyPath.IsNull() && r.providerConfig.BastionKeyPath.ValueString() != "" {
			config.BastionKeyPath = r.providerConfig.BastionKeyPath.ValueString()
		}
		if !r.providerConfig.BastionPassword.IsNull() {
			config.BastionPassword = r.providerConfig.BastionPassword.ValueString()
		}
	}

	// Check insecure host key setting.
	if !data.InsecureIgnoreHostKey.IsNull() && data.InsecureIgnoreHostKey.ValueBool() {
		config.InsecureIgnoreHostKey = true
	} else if r.providerConfig != nil && !r.providerConfig.InsecureIgnoreHostKey.IsNull() {
		config.InsecureIgnoreHostKey = r.providerConfig.InsecureIgnoreHostKey.ValueBool()
	}

	return config
}

// createSSHClient creates an SSH client.
func (r *StackResource) createSSHClient(data *StackResourceModel) (ssh.ClientInterface, error) {
	config := r.getSSHConfig(data)

	factory := r.sshClientFactory
	if factory == nil {
		factory = DefaultSSHClientFactory
	}
	return factory(config)
}

// validateComposeFile validates the compose file using docker compose config.
func (r *StackResource) validateComposeFile(ctx context.Context, client ssh.ClientInterface, remotePath string) error {
	dir := filepath.Dir(remotePath)
	file := filepath.Base(remotePath)

	cmd := fmt.Sprintf("cd %s && docker compose -f %s config --quiet", ssh.ShellQuote(dir), ssh.ShellQuote(file))
	_, stderr, err := client.RunCommand(ctx, cmd)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%s: %s", err.Error(), stderr)
		}
		return err
	}
	return nil
}

// composeUp runs docker compose up -d.
func (r *StackResource) composeUp(ctx context.Context, client ssh.ClientInterface, remotePath string) error {
	dir := filepath.Dir(remotePath)
	file := filepath.Base(remotePath)

	cmd := fmt.Sprintf("cd %s && docker compose -f %s up -d", ssh.ShellQuote(dir), ssh.ShellQuote(file))
	_, stderr, err := client.RunCommand(ctx, cmd)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%s: %s", err.Error(), stderr)
		}
		return err
	}
	return nil
}

// composeDown runs docker compose down.
func (r *StackResource) composeDown(ctx context.Context, client ssh.ClientInterface, remotePath string) error {
	dir := filepath.Dir(remotePath)
	file := filepath.Base(remotePath)

	cmd := fmt.Sprintf("cd %s && docker compose -f %s down", ssh.ShellQuote(dir), ssh.ShellQuote(file))
	_, stderr, err := client.RunCommand(ctx, cmd)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%s: %s", err.Error(), stderr)
		}
		return err
	}
	return nil
}

// hashContent computes SHA256 hash of content.
func hashContent(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// contentHashPlanModifier computes the content hash during planning.
type contentHashPlanModifier struct{}

func (m contentHashPlanModifier) Description(_ context.Context) string {
	return "Computes hash from compose file content to detect changes."
}

func (m contentHashPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes hash from compose file content to detect changes."
}

func (m contentHashPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var content types.String
	diags := req.Plan.GetAttribute(ctx, path.Root("content"), &content)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() || content.IsUnknown() || content.IsNull() {
		return
	}

	hash := hashContent(content.ValueString())
	resp.PlanValue = types.StringValue(hash)
}
