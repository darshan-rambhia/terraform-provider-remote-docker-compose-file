provider "remote-docker-compose-file" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
}

resource "remote_docker_compose_file_stack" "app" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/app/docker-compose.yaml"
  content     = file("docker-compose.yaml")
  up          = true
}
