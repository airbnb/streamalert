terraform {
  required_version = "~> 1.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.60.0, < 4.0.0"
    }
  }
}
