// Cloudwatch Event Rule: Capture CloudWatch Events
resource "aws_cloudwatch_event_rule" "capture_events" {
  name          = "${var.prefix}_${var.cluster}_streamalert_all_events"
  description   = "Capture CloudWatch events"
  role_arn      = aws_iam_role.cloudwatch_events_role.arn
  event_pattern = var.event_pattern

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// The Kinesis destination for Cloudwatch events
resource "aws_cloudwatch_event_target" "kinesis" {
  target_id = "${var.prefix}_${var.cluster}_streamalert_kinesis"
  rule      = aws_cloudwatch_event_rule.capture_events.name
  role_arn  = aws_iam_role.cloudwatch_events_role.arn
  arn       = var.kinesis_arn
}

// IAM Role: CloudWatch Events
resource "aws_iam_role" "cloudwatch_events_role" {
  name               = "${var.prefix}_${var.cluster}_cloudwatch_events_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_events_role_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

data "aws_iam_policy_document" "cloudwatch_events_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

// IAM Policy: Allow CloudWatch to write events to Kinesis Streams
resource "aws_iam_role_policy" "cloudwatch_events_policy" {
  name   = "CloudWatchEventsToKinesis"
  role   = aws_iam_role.cloudwatch_events_role.id
  policy = data.aws_iam_policy_document.kinesis_put_records.json
}

data "aws_iam_policy_document" "kinesis_put_records" {

  statement {
    sid = "CloudWatchEventsPutKinesisRecords"

    actions = [
      "kinesis:PutRecord",
      "kinesis:PutRecords",
    ]

    resources = [
      var.kinesis_arn,
    ]
  }
}
