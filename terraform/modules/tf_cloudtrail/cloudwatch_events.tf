// Cloudwatch event to capture Cloudtrail API calls
resource "aws_cloudwatch_event_rule" "all_events" {
  count         = "${var.enable_kinesis ? 1 : 0}"
  name          = "${var.prefix}_${var.cluster}_streamalert_all_events"
  description   = "Capture all CloudWatch events"
  role_arn      = "${aws_iam_role.streamalert_cloudwatch_role.arn}"
  event_pattern = "${var.event_pattern}"
}

// The Kinesis destination for Cloudwatch events
resource "aws_cloudwatch_event_target" "kinesis" {
  count = "${var.enable_kinesis ? 1 : 0}"
  rule  = "${aws_cloudwatch_event_rule.all_events.name}"
  arn   = "${var.kinesis_arn}"
}

// IAM Role: CloudWatch Events
resource "aws_iam_role" "streamalert_cloudwatch_role" {
  count = "${var.enable_kinesis ? 1 : 0}"
  name  = "${var.prefix}_${var.cluster}_streamalert_cloudwatch_role"
  path  = "/streamalert/"

  assume_role_policy = "${data.aws_iam_policy_document.streamalert_cloudwatch_role_assume_role_policy.json}"
}

data "aws_iam_policy_document" "streamalert_cloudwatch_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

// IAM Policy: Allow CloudWatch to write events to Kinesis Streams
resource "aws_iam_role_policy" "streamalert_cloudwatch_policy" {
  count = "${var.enable_kinesis ? 1 : 0}"
  name  = "${var.prefix}_${var.cluster}_streamalert_cloudwatch"
  role  = "${aws_iam_role.streamalert_cloudwatch_role.id}"

  policy = "${data.aws_iam_policy_document.kinesis_put_records.json}"
}

data "aws_iam_policy_document" "kinesis_put_records" {
  count = "${var.enable_kinesis ? 1 : 0}"

  statement {
    sid = "CloudWatchEventsPutKinesisRecords"

    actions = [
      "kinesis:PutRecord",
      "kinesis:PutRecords",
    ]

    resources = [
      "${var.kinesis_arn}",
    ]
  }
}
