// IAM Role: CloudWatch Events
resource "aws_iam_role" "streamalert_cloudwatch_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_cloudwatch_role"
  path = "/streamalert/"

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
  name = "${var.prefix}_${var.cluster}_streamalert_cloudwatch"
  role = "${aws_iam_role.streamalert_cloudwatch_role.id}"

  policy = "${data.aws_iam_policy_document.kinesis_put_records.json}"
}

data "aws_iam_policy_document" "kinesis_put_records" {
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
