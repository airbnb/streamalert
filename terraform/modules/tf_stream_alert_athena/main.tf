// S3 Bucket: Athena Query Results and Metastore Bucket
resource "aws_s3_bucket" "athena_results_bucket" {
  bucket        = "${var.results_bucket}"
  acl           = "private"
  force_destroy = false

  tags {
    Name = "StreamAlert"
  }

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${var.s3_logging_bucket}"
    target_prefix = "${var.results_bucket}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "${var.kms_key_id}"
      }
    }
  }
}

// Athena Database: streamalert
resource "aws_athena_database" "streamalert" {
  name   = "${var.database_name}"
  bucket = "${aws_s3_bucket.athena_results_bucket.bucket}"
}

// Log Retention Policy
resource "aws_cloudwatch_log_group" "athena" {
  name              = "/aws/lambda/${var.prefix}_streamalert_athena_partition_refresh"
  retention_in_days = 14
}
