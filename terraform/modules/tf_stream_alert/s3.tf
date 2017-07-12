// S3 Bucket: Store StreamAlerts from the Alert Processor
resource "aws_s3_bucket" "streamalerts" {
  bucket        = "${replace("${var.prefix}.${var.cluster}.streamalerts", "_", ".")}"
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${var.s3_logging_bucket}"
    target_prefix = "${replace("${var.prefix}.${var.cluster}.streamalerts", "_", ".")}/"
  }
}
