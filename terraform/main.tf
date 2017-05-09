// Make sure you export the following environment variables!
//   export AWS_ACCESS_KEY_ID="access-key"
//   export AWS_SECRET_ACCESS_KEY="secret-key"
//   export AWS_DEFAULT_REGION="region"
provider "aws" {}

// Store the Terraform Statefile in S3
// Upgrade instructions: https://www.terraform.io/upgrade-guides/0-9.html
terraform {
  required_version = "> 0.9.0"

  backend "s3" {
    bucket     = "${aws_s3_bucket.terraform_remote_state.id}"
    key        = "${lookup(var.terraform, "tfstate_s3_key")}"
    region     = "${lookup(var.account, "region")}"
    encrypt    = true
    acl        = "private"
    kms_key_id = "alias/${lookup(var.account, "kms_key_alias")}"
  }
}

// Setup StreamAlert source code S3 bucket
// This bucket must be created first
resource "aws_s3_bucket" "lambda_source" {
  bucket        = "${lookup(var.rule_processor_config, "source_bucket")}"
  acl           = "private"
  force_destroy = true
}

// Setup Terraform tfstate bucket
resource "aws_s3_bucket" "terraform_remote_state" {
  bucket        = "${lookup(var.account, "prefix")}.streamalert.terraform.state"
  acl           = "private"
  force_destroy = true

  versioning {
    enabled = true
  }
}

// Setup StreamAlert S3 bucket for creds
resource "aws_s3_bucket" "stream_alert_secrets" {
  bucket        = "${lookup(var.account, "prefix")}.streamalert.secrets"
  acl           = "private"
  force_destroy = true

  versioning {
    enabled = true
  }
}

resource "aws_kms_key" "stream_alert_secrets" {
  enable_key_rotation = true
  description         = "StreamAlert secrets management"
}

resource "aws_kms_alias" "stream_alert_secrets" {
  name          = "alias/stream_alert_secrets"
  target_key_id = "${aws_kms_key.stream_alert_secrets.key_id}"
}
