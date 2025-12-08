terraform {
  required_providers {
    docker_compose = {
      source  = "darshan-rambhia/docker-compose"
      version = "~> 0.1"
    }
  }
}

provider "docker_compose" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
  # Or use ssh_private_key for inline key content
  # ssh_password = "password"  # For password auth
}

# Deploy a simple nginx stack
resource "docker_compose_stack" "web" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/web/docker-compose.yaml"

  content = <<-EOT
    version: "3.8"
    services:
      nginx:
        image: nginx:alpine
        ports:
          - "80:80"
        restart: unless-stopped
  EOT

  up       = true # Run 'docker compose up -d' after upload
  validate = true # Validate compose file before applying

  # Override provider-level SSH settings if needed
  # ssh_user = "deploy"
  # ssh_key_path = "~/.ssh/deploy_key"
}

# Output the stack ID for reference
output "stack_id" {
  value = docker_compose_stack.web.id
}

output "content_hash" {
  value = docker_compose_stack.web.content_hash
}
