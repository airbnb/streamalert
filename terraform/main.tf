// Make sure you export the following environment variables!
//    export AWS_ACCESS_KEY_ID="access-key"
 //   export AWS_SECRET_ACCESS_KEY="secret-key"
 //   export AWS_DEFAULT_REGION="region"
provider "aws" {}

// store tfstate file in s3 using the terraform_tfstate_key
// data "terraform_remote_state" "tfstate_stream_alert" {
//   backend = "s3"
// 
//   config {
//     bucket     = "${var.lambda_source_bucket_name}"
//     key        = "${var.tfstate_s3_key}"
//     region     = "${var.region}"
//     // encrypt    = true
//     acl        = "private"
//     // kms_key_id = "alias/${var.kms_key_alias}"
//   }
// }

// Setup StreamAlert source code S3 bucket
// This bucket must be created first
resource "aws_s3_bucket" "lambda_source" {
  bucket        = "${var.lambda_source_bucket_name}"
  acl           = "private"
  force_destroy = true
}

// Setup integration testing bucket
resource "aws_s3_bucket" "integration_testing" {
  bucket        = "${var.prefix}.streamalert.testing.results"
  acl           = "private"
  force_destroy = true
}

resource "aws_kms_key" "stream_alert_secrets" {
  enable_key_rotation = true
  description         = "StreamAlert secrets management"
}

resource "aws_kms_alias" "stream_alert_secrets" {
  name          = "alias/stream_alert_secrets"
  target_key_id = "${aws_kms_key.stream_alert_secrets.key_id}"
}
