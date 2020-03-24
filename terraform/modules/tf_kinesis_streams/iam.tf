// IAM User: streamalert user for systems to send data to the stream
resource "aws_iam_user" "streamalert" {
  count = var.create_user ? 1 : 0
  name  = "${var.prefix}_${var.cluster}_streamalert_user"
  path  = "/streamalert/"

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Group: streamalert clustered group
resource "aws_iam_group" "streamalert" {
  count = var.create_user ? 1 : 0
  name  = "${var.prefix}_${var.cluster}_streamalert_users"
  path  = "/streamalert/"
}

// IAM Group Membership: Assign streamalert user to group
resource "aws_iam_group_membership" "streamalert" {
  count = var.create_user ? 1 : 0
  name  = "streamalert-kinesis-user-membership"

  users = [
    aws_iam_user.streamalert[0].name,
  ]

  group = aws_iam_group.streamalert[0].name
}

// IAM Group Policy: Allow users in the group to PutRecords to Kinesis
resource "aws_iam_group_policy" "streamalert_kinesis_put_records" {
  count  = var.create_user ? 1 : 0
  name   = "KinesisPutRecords"
  group  = aws_iam_group.streamalert[0].id
  policy = data.aws_iam_policy_document.streamalert_writeonly[0].json
}

// IAM Access Key: credentials for the above user
resource "aws_iam_access_key" "streamalert" {
  count = var.create_user ? var.access_key_count : 0
  user  = aws_iam_user.streamalert[0].name
}

// IAM Policy Doc: allow the streamalert user to write to the generated Kinesis Stream
data "aws_iam_policy_document" "streamalert_writeonly" {
  count = var.create_user || length(var.trusted_accounts) > 0 ? 1 : 0

  statement {
    actions = [
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
      "kinesis:PutRecord*",
    ]

    resources = [
      aws_kinesis_stream.streamalert_stream.arn,
    ]
  }
}

// IAM Policy Document: policy document to allow specified account to assume the role
data "aws_iam_policy_document" "streamalert_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = formatlist("arn:aws:iam::%s:root", var.trusted_accounts)
    }
  }
}

// IAM Role: streamalert role for systems in another account to send data to the stream
resource "aws_iam_role" "streamalert_write_role" {
  count              = length(var.trusted_accounts) > 0 ? 1 : 0
  name               = "${var.prefix}_${var.cluster}_streamalert_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.streamalert_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Role Policy: policy to allow a role to send data to the stream
resource "aws_iam_role_policy" "streamalert_kinesis_put_records" {
  count  = length(var.trusted_accounts) > 0 ? 1 : 0
  name   = "KinesisPutRecords"
  role   = aws_iam_role.streamalert_write_role[0].id
  policy = data.aws_iam_policy_document.streamalert_writeonly[0].json
}
