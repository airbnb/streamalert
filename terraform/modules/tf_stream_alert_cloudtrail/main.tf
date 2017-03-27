// StreamAlert CloudTrail
resource "aws_cloudtrail" "streamalert" {
  name                          = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail_bucket.id}"
  s3_key_prefix                 = "cloudtrail"
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

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Sid": "AWSCloudTrailAclCheck",
          "Effect": "Allow",
          "Principal": {
            "Service": "cloudtrail.amazonaws.com"
          },
          "Action": "s3:GetBucketAcl",
          "Resource": "arn:aws:s3:::${var.prefix}.${var.cluster}.streamalert.cloudtrail"
      },
      {
          "Sid": "AWSCloudTrailWrite",
          "Effect": "Allow",
          "Principal": {
            "Service": "cloudtrail.amazonaws.com"
          },
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::${var.prefix}.${var.cluster}.streamalert.cloudtrail/*",
          "Condition": {
              "StringEquals": {
                  "s3:x-amz-acl": "bucket-owner-full-control"
              }
          }
      }
  ]
}
POLICY

  tags {
    Name    = "${var.prefix}.${var.cluster}.streamalert.cloudtrail"
    Cluster = "${var.cluster}"
  }
}

// Cloudwatch event to capture Cloudtrail API calls
resource "aws_cloudwatch_event_rule" "all_events" {
  name        = "${var.prefix}_${var.cluster}_streamalert_all_events"
  description = "Capture all CloudWatch events"
  role_arn    = "${aws_iam_role.streamalert_cloudwatch_role.arn}"

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ]
}
PATTERN
}

// The Kinesis destination for Cloudwatch events
resource "aws_cloudwatch_event_target" "kinesis" {
  rule = "${aws_cloudwatch_event_rule.all_events.name}"
  arn  = "${var.kinesis_arn}"
}
