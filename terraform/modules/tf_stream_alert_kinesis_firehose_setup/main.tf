resource "aws_s3_bucket" "stream_alert_data" {
  bucket        = "${var.s3_bucket_name}"
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${var.s3_logging_bucket}"
    target_prefix = "${var.s3_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "${var.kms_key_id}"
      }
    }
  }

  tags {
    Name = "${var.s3_bucket_name}"
  }
}
