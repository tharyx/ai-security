# BAD fixture: breaks every rule of the validator. All secrets are fake canaries.
packer {
  required_plugins {
    amazon = {
      version = ">= 0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "ssh_password" {
  type    = string
  default = "CANARY-not-a-real-password"
}

source "amazon-ebs" "base" {
  region     = "eu-west-1"
  access_key = "CANARY-NOT-A-KEY"
  source_ami_filter {
    filters = {
      name = "debian-12-amd64-*"
    }
    most_recent = true
  }
  instance_type = "t3.small"
  ssh_username  = "admin"
}

build {
  sources = ["source.amazon-ebs.base", "source.amazon-ebs.missing"]

  provisioner "shell" {
    inline = ["curl -fsSL http://scripts.example/install.sh | bash"]
  }
}
