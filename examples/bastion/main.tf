terraform {
  required_providers {
    remote-docker-compose-file = {
      source  = "darshan-rambhia/remote-docker-compose-file"
      version = "~> 0.1"
    }
  }
}

provider "remote-docker-compose-file" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
}

# Deploy to an internal host via a bastion/jump host
# Useful for accessing hosts in private networks or behind firewalls
resource "remote_docker_compose_file_stack" "internal_service" {
  host        = "10.0.1.50" # Internal IP address (not directly accessible)
  remote_path = "/opt/stacks/internal/docker-compose.yaml"

  content = <<-EOT
    version: "3.8"
    services:
      api:
        image: internal-api:latest
        ports:
          - "3000:3000"
        environment:
          DATABASE_URL: postgres://postgres:password@db:5432/mydb
        restart: unless-stopped

      db:
        image: postgres:15-alpine
        environment:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: mydb
        volumes:
          - db_data:/var/lib/postgresql/data
        restart: unless-stopped

    volumes:
      db_data:
  EOT

  up       = true
  validate = true

  # Direct connection settings
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"

  # Bastion/jump host configuration
  bastion_host     = "bastion.example.com"
  bastion_port     = 22
  bastion_user     = "jumpuser"
  bastion_key_path = "~/.ssh/bastion_key"
  # Alternatively, use bastion_private_key for inline key content
  # bastion_private_key = file("~/.ssh/bastion_key")
}

output "stack_id" {
  value = remote_docker_compose_file_stack.internal_service.id
}

output "content_hash" {
  value = remote_docker_compose_file_stack.internal_service.content_hash
}
