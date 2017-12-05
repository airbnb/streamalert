// StreamAlert CloudTrail
resource "aws_cloudtrail" "streamalert" {
  count                         = "${var.existing_trail ? 0 : 1}"
  name                          = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail_bucket.id}"
  enable_log_file_validation    = true
  enable_logging                = "${var.enable_logging}"
  include_global_service_events = true
  is_multi_region_trail         = "${var.is_global_trail}"
}

// S3 bucket for CloudTrail output
resource "aws_s3_bucket" "cloudtrail_bucket" {
  count         = "${var.existing_trail ? 0 : 1}"
  bucket        = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
  force_destroy = false

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${var.s3_logging_bucket}"
    target_prefix = "${var.prefix}.${var.cluster}.streamalert.cloudtrail/"
  }

  policy = "${data.aws_iam_policy_document.cloudtrail_bucket.json}"

  tags {
    Name    = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
    Cluster = "${var.cluster}"
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = "${var.existing_trail ? 0 : 1}"

  statement {
    sid = "AWSCloudTrailAclCheck"

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}.${var.cluster}.streamalert.cloudtrail",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid = "AWSCloudTrailWrite"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${formatlist("arn:aws:s3:::${var.prefix}.${var.cluster}.streamalert.cloudtrail/AWSLogs/%s/*", var.account_ids)}",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}
