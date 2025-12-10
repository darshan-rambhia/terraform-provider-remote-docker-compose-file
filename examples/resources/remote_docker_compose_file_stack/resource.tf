resource "remote_docker_compose_file_stack" "web" {
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

  up       = true
  validate = true
}
