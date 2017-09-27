// AWS Kinesis Stream
resource "aws_kinesis_stream" "stream_alert_stream" {
  name             = "${var.stream_name}"
  shard_count      = "${var.shards}"
  retention_period = "${var.retention}"

  shard_level_metrics = [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
    "WriteProvisionedThroughputExceeded",
    "ReadProvisionedThroughputExceeded",
    "IteratorAgeMilliseconds",
  ]

  tags {
    Name    = "StreamAlert"
    Cluster = "${var.cluster_name}"
  }
}

// IAM User: stream_alert user for systems to send data to the stream
resource "aws_iam_user" "stream_alert" {
  name = "${var.prefix}_${var.cluster_name}_stream_alert_user"
  path = "/streamalert/"
}

// IAM Access Key: credentials for the above user
resource "aws_iam_access_key" "stream_alert" {
  count = "${var.access_key_count}"
  user  = "${aws_iam_user.stream_alert.name}"
}

// IAM Policy Doc: allow the stream_alert user to write to the generated Kinesis Stream
data "aws_iam_policy_document" "stream_alert_writeonly" {
  statement {
    actions = [
      "kinesis:PutRecord*",
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
    ]

    resources = [
      "${aws_kinesis_stream.stream_alert_stream.arn}",
    ]
  }
}

// IAM Policy Attach: associate the above policy with the stream_alert user
resource "aws_iam_user_policy" "kinesis_writeonly" {
  name = "kinesis_writeonly"
  user = "${aws_iam_user.stream_alert.name}"

  policy = "${data.aws_iam_policy_document.stream_alert_writeonly.json}"
}
