// StreamAlert CloudTrail
resource "aws_cloudtrail" "streamalert" {
  name                          = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail_bucket.id}"
  s3_key_prefix                 = "cloudtrail"
  enable_log_file_validation    = true
  enable_logging                = "${var.enable_logging}"
  include_global_service_events = true
  is_multi_region_trail         = "${var.is_global_trail}"
  count                         = "${var.existing_trail ? 0 : 1}"
}

// S3 bucket for CloudTrail output
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
  force_destroy = false
  count         = "${var.existing_trail ? 0 : 1}"

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
      "arn:aws:s3:::${var.prefix}.${var.cluster}.streamalert.cloudtrail/*",
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

// Cloudwatch event to capture Cloudtrail API calls
resource "aws_cloudwatch_event_rule" "all_events" {
  name          = "${var.prefix}_${var.cluster}_streamalert_all_events"
  description   = "Capture all CloudWatch events"
  role_arn      = "${aws_iam_role.streamalert_cloudwatch_role.arn}"
  event_pattern = "${var.event_pattern}"
}

// The Kinesis destination for Cloudwatch events
resource "aws_cloudwatch_event_target" "kinesis" {
  rule = "${aws_cloudwatch_event_rule.all_events.name}"
  arn  = "${var.kinesis_arn}"
}
