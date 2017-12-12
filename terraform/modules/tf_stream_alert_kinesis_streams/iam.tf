// IAM User: stream_alert user for systems to send data to the stream
resource "aws_iam_user" "stream_alert" {
  count = "${var.create_user ? 1 : 0}"
  name  = "${var.prefix}_${var.cluster_name}_stream_alert_user"
  path  = "/streamalert/"
}

// IAM Group: stream_alert clustered group
resource "aws_iam_group" "stream_alert" {
  count = "${var.create_user ? 1 : 0}"
  name  = "${var.prefix}_${var.cluster_name}_stream_alert_users"
  path  = "/"
}

// IAM Group Membership: Assign stream_alert user to group
resource "aws_iam_group_membership" "stream_alert" {
  count = "${var.create_user ? 1 : 0}"
  name  = "stream-alert-kinesis-user-membership"

  users = [
    "${aws_iam_user.stream_alert.name}",
  ]

  group = "${aws_iam_group.stream_alert.name}"
}

// IAM Group Policy: Allow users in the group to PutRecords to Kinesis
resource "aws_iam_group_policy" "stream_alert_kinesis_put_records" {
  count = "${var.create_user ? 1 : 0}"
  name  = "KinesisPutRecords"
  group = "${aws_iam_group.stream_alert.id}"

  policy = "${data.aws_iam_policy_document.stream_alert_writeonly.json}"
}

// IAM Access Key: credentials for the above user
resource "aws_iam_access_key" "stream_alert" {
  count = "${var.create_user ? var.access_key_count : 0}"
  user  = "${aws_iam_user.stream_alert.name}"
}

// IAM Policy Doc: allow the stream_alert user to write to the generated Kinesis Stream
data "aws_iam_policy_document" "stream_alert_writeonly" {
  count = "${var.create_user ? 1 : 0}"

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
