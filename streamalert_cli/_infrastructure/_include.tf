terraform {
  required_version = var.terraform_version

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.3.0"
    }
  }
}
