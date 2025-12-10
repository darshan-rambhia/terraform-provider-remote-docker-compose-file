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

# Deploy a stack without auto-starting containers
# Useful when you want to validate the compose file but manage container lifecycle separately
resource "remote_docker_compose_file_stack" "app" {
  host        = "192.168.1.101"
  remote_path = "/opt/stacks/app/docker-compose.yaml"

  content = <<-EOT
    version: "3.8"
    services:
      postgres:
        image: postgres:15-alpine
        environment:
          POSTGRES_PASSWORD: secretpassword
        volumes:
          - postgres_data:/var/lib/postgresql/data
        restart: unless-stopped

      app:
        image: myapp:latest
        depends_on:
          - postgres
        ports:
          - "8080:8080"
        restart: unless-stopped

    volumes:
      postgres_data:
  EOT

  up       = false # Do NOT run 'docker compose up -d' automatically
  validate = true  # Still validate the compose file

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}

output "stack_id" {
  value = remote_docker_compose_file_stack.app.id
}

output "content_hash" {
  value = remote_docker_compose_file_stack.app.content_hash
}
