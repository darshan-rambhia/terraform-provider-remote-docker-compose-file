package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure DockerComposeProvider satisfies various provider interfaces.
var _ provider.Provider = &DockerComposeProvider{}

// DockerComposeProvider defines the provider implementation.
type DockerComposeProvider struct {
	version string
}

// DockerComposeProviderModel describes the provider data model.
type DockerComposeProviderModel struct {
	// Default SSH settings that can be overridden per-resource.
	SSHUser       types.String `tfsdk:"ssh_user"`
	SSHPrivateKey types.String `tfsdk:"ssh_private_key"`
	SSHKeyPath    types.String `tfsdk:"ssh_key_path"`
	SSHPort       types.Int64  `tfsdk:"ssh_port"`

	// Additional authentication methods.
	SSHPassword        types.String `tfsdk:"ssh_password"`
	SSHCertificate     types.String `tfsdk:"ssh_certificate"`
	SSHCertificatePath types.String `tfsdk:"ssh_certificate_path"`

	// Bastion/Jump host settings.
	BastionHost     types.String `tfsdk:"bastion_host"`
	BastionPort     types.Int64  `tfsdk:"bastion_port"`
	BastionUser     types.String `tfsdk:"bastion_user"`
	BastionKey      types.String `tfsdk:"bastion_private_key"`
	BastionKeyPath  types.String `tfsdk:"bastion_key_path"`
	BastionPassword types.String `tfsdk:"bastion_password"`

	// Host key verification.
	InsecureIgnoreHostKey types.Bool `tfsdk:"insecure_ignore_host_key"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &DockerComposeProvider{
			version: version,
		}
	}
}

func (p *DockerComposeProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "remote-docker-compose-file"
	resp.Version = p.version
}

func (p *DockerComposeProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
The docker_compose provider manages Docker Compose files on remote hosts via SSH.

This provider:
- Uploads docker-compose files to remote hosts
- Optionally runs 'docker compose up -d' and 'docker compose down'
- Tracks file state in Terraform (not container state)
- Validates compose files before applying
- Supports bastion/jump hosts for multi-hop SSH

## Example Usage

` + "```hcl" + `
provider "remote_docker_compose_file" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
}

resource "remote_docker_compose_file_stack" "app" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/app/docker-compose.yaml"
  content     = file("docker-compose.yaml")
  up          = true
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "Default SSH user for connections. Can be overridden per-resource.",
				Optional:            true,
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "Default SSH private key content (sensitive). Mutually exclusive with ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH private key file. Mutually exclusive with ssh_private_key.",
				Optional:            true,
			},
			"ssh_port": schema.Int64Attribute{
				MarkdownDescription: "Default SSH port. Defaults to 22.",
				Optional:            true,
			},
			"ssh_password": schema.StringAttribute{
				MarkdownDescription: "Default SSH password for password authentication (sensitive). Use this as an alternative to key-based authentication.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate": schema.StringAttribute{
				MarkdownDescription: "Default SSH certificate content for certificate authentication. Used with ssh_private_key or ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH certificate file for certificate authentication. Used with ssh_private_key or ssh_key_path.",
				Optional:            true,
			},
			"bastion_host": schema.StringAttribute{
				MarkdownDescription: "Default bastion/jump host address for multi-hop SSH connections.",
				Optional:            true,
			},
			"bastion_port": schema.Int64Attribute{
				MarkdownDescription: "Default bastion host SSH port. Defaults to 22.",
				Optional:            true,
			},
			"bastion_user": schema.StringAttribute{
				MarkdownDescription: "Default SSH user for bastion host. Falls back to ssh_user if not set.",
				Optional:            true,
			},
			"bastion_private_key": schema.StringAttribute{
				MarkdownDescription: "Default SSH private key content for bastion host (sensitive). Falls back to ssh_private_key if not set.",
				Optional:            true,
				Sensitive:           true,
			},
			"bastion_key_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH private key file for bastion host. Falls back to ssh_key_path if not set.",
				Optional:            true,
			},
			"bastion_password": schema.StringAttribute{
				MarkdownDescription: "Default SSH password for bastion host (sensitive).",
				Optional:            true,
				Sensitive:           true,
			},
			"insecure_ignore_host_key": schema.BoolAttribute{
				MarkdownDescription: "Skip SSH host key verification. WARNING: This is insecure and should only be used for testing. Defaults to false.",
				Optional:            true,
			},
		},
	}
}

func (p *DockerComposeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config DockerComposeProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Make provider config available to resources.
	resp.DataSourceData = &config
	resp.ResourceData = &config
}

func (p *DockerComposeProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewStackResource,
	}
}

func (p *DockerComposeProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
