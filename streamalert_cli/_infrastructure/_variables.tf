variable "terraform_version" {
  type    = string
  default = "~> 0.13.0"
}

variable "aws_provider_version" {
  type    = string
  default = "~> 3.3.0"
}

variable "region" {
  type = string
}
