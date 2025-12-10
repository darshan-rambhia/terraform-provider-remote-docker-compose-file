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

# This resource can be imported from an existing docker compose stack on a remote host
#
# To import an existing stack:
#   terraform import remote_docker_compose_file_stack.web 192.168.1.100:/opt/stacks/web/docker-compose.yaml
#
# After importing, you need to define the resource configuration and provide the compose file content
resource "remote_docker_compose_file_stack" "web" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/web/docker-compose.yaml"

  # Read the compose file content from your local source
  content = file("${path.module}/docker-compose.yaml")

  # After import, the up flag is typically false so it doesn't restart containers
  up       = false
  validate = true

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}

output "stack_id" {
  value = remote_docker_compose_file_stack.web.id
}

output "content_hash" {
  value = remote_docker_compose_file_stack.web.content_hash
}
