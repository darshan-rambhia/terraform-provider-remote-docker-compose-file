resource "remote_docker_compose_file_stack" "web" {
  host        = "192.168.1.100"
  remote_path = "/opt/stacks/web/docker-compose.yaml"
  content     = file("${path.module}/docker-compose.yaml")
  up          = true
  validate    = true

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}
