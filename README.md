# Terraform Provider for Remote Docker Compose Files

A Terraform provider for managing Docker Compose files on remote hosts via SSH.

## Overview

The `remote-docker-compose-file` provider enables you to:
- Upload Docker Compose files to remote hosts
- Optionally validate compose files before applying
- Optionally run `docker compose up -d` to start services
- Optionally run `docker compose down` to stop services
- Track file state in Terraform (not container state)
- Support bastion/jump hosts for multi-hop SSH connections

**Note:** This provider tracks the state of Docker Compose files, not the containers themselves. Use it to manage the lifecycle of compose file deployments, not container orchestration.

## Installation

Download and extract the latest release for your platform from the [releases page](https://github.com/darshan-rambhia/terraform-provider-remote-docker-compose-file/releases), then place it in your Terraform plugins directory:

```bash
mkdir -p ~/.terraform.d/plugins/local.providers/darshan-rambhia/remote-docker-compose-file/1.0.0/darwin_amd64
mv terraform-provider-remote-docker-compose-file_v1.0.0_darwin_amd64 ~/.terraform.d/plugins/local.providers/darshan-rambhia/remote-docker-compose-file/1.0.0/darwin_amd64/
```

Or configure in your `.terraformrc`:

```hcl
provider_installation {
  direct {
    "local.providers/darshan-rambhia/remote-docker-compose-file" = "/path/to/plugins"
  }
}
```

## Quick Start

### Basic Example

```hcl
terraform {
  required_providers {
    remote_docker_compose_file = {
      source = "local.providers/darshan-rambhia/remote-docker-compose-file"
    }
  }
}

provider "remote_docker_compose_file" {
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/id_ed25519"
}

resource "remote_docker_compose_file_stack" "web" {
  host        = "192.168.1.100"
  remote_path = "/opt/docker-compose/web/docker-compose.yaml"
  content     = file("${path.module}/docker-compose.yaml")
  up          = true
}
```

### With Validation

```hcl
resource "remote_docker_compose_file_stack" "app" {
  host        = "app.example.com"
  remote_path = "/etc/docker/compose/app/docker-compose.yaml"
  content     = file("./compose.yaml")

  # Validate the compose file before applying
  validate = true

  # Don't start services, just upload the file
  up = false
}
```

### With Bastion Host

```hcl
provider "remote_docker_compose_file" {
  ssh_user            = "deploy"
  ssh_key_path        = "~/.ssh/id_ed25519"
  bastion_host        = "bastion.example.com"
  bastion_user        = "bastion-user"
  bastion_key_path    = "~/.ssh/bastion_key"
}

resource "remote_docker_compose_file_stack" "internal" {
  host        = "10.0.1.50"
  remote_path = "/opt/stacks/internal/docker-compose.yaml"
  content     = file("./docker-compose.yaml")
  up          = true
}
```

## Provider Configuration

### Provider Arguments

- `ssh_user` (Optional) - SSH user for connections. Defaults to system user. Can be overridden per-resource.
- `ssh_private_key` (Optional) - SSH private key content (sensitive). Mutually exclusive with `ssh_key_path`.
- `ssh_key_path` (Optional) - Path to SSH private key file. Mutually exclusive with `ssh_private_key`.
- `ssh_port` (Optional) - SSH port. Defaults to 22.
- `ssh_password` (Optional) - SSH password for password authentication (sensitive). Use as alternative to key-based auth.
- `ssh_certificate` (Optional) - SSH certificate content for certificate authentication.
- `ssh_certificate_path` (Optional) - Path to SSH certificate file for certificate authentication.
- `bastion_host` (Optional) - Bastion/jump host address for multi-hop SSH connections.
- `bastion_port` (Optional) - Bastion host SSH port. Defaults to 22.
- `bastion_user` (Optional) - SSH user for bastion. Falls back to `ssh_user` if not set.
- `bastion_private_key` (Optional) - SSH private key for bastion (sensitive). Falls back to `ssh_private_key` if not set.
- `bastion_key_path` (Optional) - Path to SSH private key for bastion. Falls back to `ssh_key_path` if not set.
- `bastion_password` (Optional) - SSH password for bastion (sensitive).
- `insecure_ignore_host_key` (Optional) - Skip SSH host key verification. WARNING: Insecure, use only for testing. Defaults to false.

## Resource Configuration

### Resource Arguments

- `host` (Required) - Hostname or IP address of the target host.
- `remote_path` (Required) - Absolute path where the compose file will be uploaded.
- `content` (Required) - The Docker Compose file content.
- `ssh_user` (Optional) - Override provider-level SSH user.
- `ssh_private_key` (Optional) - Override provider-level SSH private key.
- `ssh_key_path` (Optional) - Override provider-level SSH key path.
- `ssh_port` (Optional) - Override provider-level SSH port.
- `ssh_password` (Optional) - Override provider-level SSH password.
- `ssh_certificate` (Optional) - Override provider-level SSH certificate.
- `ssh_certificate_path` (Optional) - Override provider-level SSH certificate path.
- `bastion_host` (Optional) - Override provider-level bastion host.
- `bastion_port` (Optional) - Override provider-level bastion port.
- `bastion_user` (Optional) - Override provider-level bastion user.
- `bastion_private_key` (Optional) - Override provider-level bastion key.
- `bastion_key_path` (Optional) - Override provider-level bastion key path.
- `bastion_password` (Optional) - Override provider-level bastion password.
- `insecure_ignore_host_key` (Optional) - Override provider-level host key verification setting.
- `up` (Optional) - Run `docker compose up -d` after uploading. Defaults to false.
- `validate` (Optional) - Validate the compose file before applying. Defaults to false.

### Resource Attributes

- `id` - The resource ID (hostname:remote_path).
- `content_hash` - SHA256 hash of the uploaded content for drift detection.

## Behavior

### Create
1. Creates SSH connection to target host
2. Uploads Docker Compose file to `remote_path`
3. If `validate = true`, runs `docker compose config` to validate
4. If `up = true`, runs `docker compose up -d`

### Read
1. Connects to remote host
2. Retrieves the current file hash for drift detection
3. Marks resource as removed if file no longer exists

### Update
1. Detects if content has changed
2. If content differs:
   - Runs `docker compose down` (if `up = true`)
   - Uploads new file content
   - Runs `docker compose up -d` (if `up = true`)

### Delete
1. Runs `docker compose down` (if `up = true`)
2. Removes the compose file from remote host

### Import
Import existing compose files by their deployment ID (format: `hostname:path`):

```bash
terraform import remote_docker_compose_file_stack.web 192.168.1.100:/opt/docker-compose/docker-compose.yaml
```

## Requirements

- Terraform 1.0 or later
- SSH access to target hosts with appropriate permissions
- Docker and `docker compose` installed on target hosts (if using `up` or `validate`)
- For validation: `docker compose config` support (Docker Compose V2 or later)

## Examples

See the [examples](./examples/) directory for more detailed usage patterns.

## Development

### Requirements

- Go 1.21 or later
- Terraform CLI (for testing)
- Docker (for acceptance tests)

### Building

```bash
go build -o terraform-provider-remote-docker-compose-file
```

### Testing

```bash
# Unit tests
go test ./...

# Acceptance tests
go test -tags=acceptance ./tests/acceptance
```

### Documentation

Generate provider documentation:

```bash
go generate -tags generate ./tools/
```

## Troubleshooting

### SSH Host Key Verification Failures

Ensure the remote host's SSH key is in your `~/.ssh/known_hosts`:

```bash
ssh-keyscan -H hostname >> ~/.ssh/known_hosts
```

Or set `insecure_ignore_host_key = true` (not recommended for production).

### Docker Compose Validation Errors

Ensure Docker Compose V2 is installed:

```bash
docker compose version
```

If using Compose V1, the `validate` argument will fail. Update to Compose V2.

### Permission Denied

Ensure the SSH user has:
- Read/write access to `remote_path` directory
- Permission to run `docker compose` commands
- Proper Docker group membership or sudo access

## Security Considerations

- Never commit sensitive data (SSH keys, passwords) to version control
- Use SSH key-based authentication over passwords
- Enable SSH host key verification in production
- Use `sensitive = true` in your Terraform code for sensitive variables
- Restrict file permissions on the target host

## License

[Your License Here]

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Support

For issues, questions, or contributions, please open an issue on [GitHub](https://github.com/darshan-rambhia/terraform-provider-remote-docker-compose-file/issues).
