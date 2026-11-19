# GOOD fixture: golden image template (HCL2). Packer + Ansible + Docker.
packer {
  required_plugins {
    docker = {
      version = "~> 1.1"
      source  = "github.com/hashicorp/docker"
    }
    ansible = {
      version = "~> 1.1"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

variable "base_image" {
  type    = string
  # Pinned by digest, not by tag. Refresh deliberately through a reviewed pull request.
  default = "debian@sha256:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
}

variable "registry_password" {
  type      = string
  sensitive = true
  # no default: injected at build time, e.g. PKR_VAR_registry_password from the CI secret store
}

source "docker" "base" {
  image  = var.base_image
  commit = true
}

build {
  name    = "golden"
  sources = ["source.docker.base"]

  provisioner "ansible" {
    playbook_file   = "./ansible/harden.yml"
    extra_arguments = ["--extra-vars", "hardening_profile=cis-l1"]
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
