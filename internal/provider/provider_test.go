package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestDockerComposeProvider_Metadata(t *testing.T) {
	t.Parallel()

	p := New("test")()
	req := provider.MetadataRequest{}
	resp := &provider.MetadataResponse{}

	p.Metadata(context.Background(), req, resp)

	if resp.TypeName != "remote-docker-compose-file" {
		t.Errorf("Metadata() TypeName = %q, want %q", resp.TypeName, "remote-docker-compose-file")
	}
	if resp.Version != "test" {
		t.Errorf("Metadata() Version = %q, want %q", resp.Version, "test")
	}
}

func TestDockerComposeProvider_Schema(t *testing.T) {
	t.Parallel()

	p := New("test")()
	req := provider.SchemaRequest{}
	resp := &provider.SchemaResponse{}

	p.Schema(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned errors: %v", resp.Diagnostics)
	}

	// Verify expected attributes exist
	expectedAttrs := []string{
		"ssh_user",
		"ssh_private_key",
		"ssh_key_path",
		"ssh_port",
		"ssh_password",
		"ssh_certificate",
		"ssh_certificate_path",
		"bastion_host",
		"bastion_port",
		"bastion_user",
		"bastion_private_key",
		"bastion_key_path",
		"bastion_password",
		"insecure_ignore_host_key",
	}

	for _, attr := range expectedAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("Schema() missing attribute %q", attr)
		}
	}
}

func TestDockerComposeProvider_Configure(t *testing.T) {
	t.Parallel()

	p := New("test")()

	// Get the schema first
	schemaReq := provider.SchemaRequest{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), schemaReq, schemaResp)

	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned errors: %v", schemaResp.Diagnostics)
	}

	tests := []struct {
		name       string
		configData map[string]tftypes.Value
		wantErr    bool
	}{
		{
			name: "empty config",
			configData: map[string]tftypes.Value{
				"ssh_user":                 tftypes.NewValue(tftypes.String, nil),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, nil),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, nil),
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
			},
			wantErr: false,
		},
		{
			name: "with ssh user",
			configData: map[string]tftypes.Value{
				"ssh_user":                 tftypes.NewValue(tftypes.String, "deploy"),
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
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, true),
			},
			wantErr: false,
		},
		{
			name: "with bastion config",
			configData: map[string]tftypes.Value{
				"ssh_user":                 tftypes.NewValue(tftypes.String, "root"),
				"ssh_private_key":          tftypes.NewValue(tftypes.String, "key-content"),
				"ssh_key_path":             tftypes.NewValue(tftypes.String, nil),
				"ssh_port":                 tftypes.NewValue(tftypes.Number, 22),
				"ssh_password":             tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate":          tftypes.NewValue(tftypes.String, nil),
				"ssh_certificate_path":     tftypes.NewValue(tftypes.String, nil),
				"bastion_host":             tftypes.NewValue(tftypes.String, "bastion.example.com"),
				"bastion_port":             tftypes.NewValue(tftypes.Number, 2222),
				"bastion_user":             tftypes.NewValue(tftypes.String, "jump-user"),
				"bastion_private_key":      tftypes.NewValue(tftypes.String, nil),
				"bastion_key_path":         tftypes.NewValue(tftypes.String, nil),
				"bastion_password":         tftypes.NewValue(tftypes.String, nil),
				"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, false),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			configValue := tftypes.NewValue(
				schemaResp.Schema.Type().TerraformType(context.Background()),
				tt.configData,
			)

			config := tfsdk.Config{
				Schema: schemaResp.Schema,
				Raw:    configValue,
			}

			req := provider.ConfigureRequest{
				Config: config,
			}
			resp := &provider.ConfigureResponse{}

			p.Configure(context.Background(), req, resp)

			if resp.Diagnostics.HasError() != tt.wantErr {
				t.Errorf("Configure() hasError = %v, wantErr %v, diagnostics: %v", resp.Diagnostics.HasError(), tt.wantErr, resp.Diagnostics)
			}

			if !tt.wantErr {
				// Verify that ResourceData is set
				if resp.ResourceData == nil {
					t.Error("Configure() should set ResourceData")
				}
				// Verify that DataSourceData is set
				if resp.DataSourceData == nil {
					t.Error("Configure() should set DataSourceData")
				}
			}
		})
	}
}

func TestDockerComposeProvider_Resources(t *testing.T) {
	t.Parallel()

	p := New("test")()
	resources := p.Resources(context.Background())

	if len(resources) != 1 {
		t.Errorf("Resources() returned %d resources, want 1", len(resources))
	}
}

func TestDockerComposeProvider_DataSources(t *testing.T) {
	t.Parallel()

	p := New("test")()
	dataSources := p.DataSources(context.Background())

	if len(dataSources) != 0 {
		t.Errorf("DataSources() returned %d data sources, want 0", len(dataSources))
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
	}{
		{name: "with version", version: "1.0.0"},
		{name: "empty version", version: ""},
		{name: "dev version", version: "dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			factory := New(tt.version)
			if factory == nil {
				t.Fatal("New() returned nil factory")
			}

			p := factory()
			if p == nil {
				t.Fatal("factory() returned nil provider")
			}
		})
	}
}
