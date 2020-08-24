locals {
  exclude_home_region_filter = "{ $$.awsRegion != \"${var.region}\" }"
}

// CloudWatch Log group to send all CloudTrail logs to
resource "aws_cloudwatch_log_group" "cloudtrail_logging" {
  name              = "CloudTrail/DefaultLogGroup"
  retention_in_days = var.retention_in_days

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Role: Allow CloudTrail logs to send logs to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_to_cloudwatch_role" {
  name               = "${var.prefix}_${var.cluster}_cloudtrail_to_cloudwatch_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Policy Document: Allow CloudTrail to AssumeRole
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_assume_role_policy" {

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

// IAM Role Policy: Allow CloudTrail logs to create log streams and put logs to CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch_create_logs" {
  name   = "CloudTrailToCloudWatchCreateLogs"
  role   = aws_iam_role.cloudtrail_to_cloudwatch_role.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_create_logs.json
}

// IAM Policy Document: Allow CloudTrail logs to create log streams and put logs to CloudWatch Logs
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_create_logs" {

  statement {
    sid       = "AWSCloudTrailCreateLogStream"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail_logging.arn}:log-stream:*"]
  }

  statement {
    sid       = "AWSCloudTrailPutLogEvents"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail_logging.arn}:log-stream:*"]
  }
}

// CloudWatch Log Subscription Filter
//   If we are collecting CloudTrail logs in the 'home region' another way, this allows
//   for suppression of logs that originated in this region.
resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_via_cloudwatch" {
  name            = "${var.prefix}_${var.cluster}_cloudtrail_delivery"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail_logging.name
  filter_pattern  = var.exclude_home_region_events ? local.exclude_home_region_filter : ""
  destination_arn = var.cloudwatch_destination_arn
  distribution    = "Random"
}
