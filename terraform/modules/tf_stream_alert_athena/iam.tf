// IAM Role: Lambda Execution Role
resource "aws_iam_role" "athena_partition_role" {
  name = "streamalert_athena_partition_refresh"

  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

// IAM Policy Doc: Generic Lambda trust relationship policy
data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// IAM Role Policy: Allow the Lambda function to use Cloudwatch logging
resource "aws_iam_role_policy" "cloudwatch" {
  name = "CloudWatchPutLogs"
  role = "${aws_iam_role.athena_partition_role.id}"

  policy = "${data.aws_iam_policy_document.cloudwatch.json}"
}

// IAM Policy Doc: Cloudwatch creation and logging of events
data "aws_iam_policy_document" "cloudwatch" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

// IAM Role Policy: Allow the Lambda function to use Cloudwatch logging
resource "aws_iam_role_policy" "sqs" {
  name = "SQSReadDeleteMessages"
  role = "${aws_iam_role.athena_partition_role.id}"

  policy = "${data.aws_iam_policy_document.sqs.json}"
}

// IAM Policy Doc: Cloudwatch creation and logging of events
data "aws_iam_policy_document" "sqs" {
  statement {
    effect = "Allow"

    actions = [
      "sqs:ListQueues",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "sqs:DeleteMessage",
      "sqs:DeleteMessageBatch",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
    ]

    resources = [
      "${aws_sqs_queue.streamalert_athena_data_bucket_notifications.arn}",
    ]
  }
}

// IAM Role Policy: Allow the Lambda function to execute Athena queries
// Ref: http://amzn.to/2tSyxUV
resource "aws_iam_role_policy" "athena_query_permissions" {
  name = "AthenaQuery"
  role = "${aws_iam_role.athena_partition_role.id}"

  policy = "${data.aws_iam_policy_document.athena_permissions.json}"
}

// IAM Policy Doc: Athena and S3 permissions
data "aws_iam_policy_document" "athena_permissions" {
  statement {
    effect = "Allow"

    actions = [
      "athena:*",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "glue:BatchCreatePartition",
      "glue:GetDatabase",
      "glue:GetDatabases",
      "glue:GetTable",
      "glue:GetTableVersions",
      "glue:GetTables",
      "glue:UpdateDatabase",
      "glue:UpdatePartition",
      "glue:UpdateTable",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
      "s3:CreateBucket",
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::aws-athena-query-results-*",
    ]
  }
}

// IAM Role Policy: Allow the Lambda function to read data buckets
resource "aws_iam_role_policy" "athena_query_data_bucket_permissions" {
  name = "AthenaGetData"
  role = "${aws_iam_role.athena_partition_role.id}"

  policy = "${data.aws_iam_policy_document.athena_data_bucket_read.json}"
}

// IAM Policy Doc: Allow Athena to read data from configured buckets
//                 This is necessary for table repairs
data "aws_iam_policy_document" "athena_data_bucket_read" {
  statement {
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
      "s3:CreateBucket",
      "s3:PutObject",
    ]

    resources = [
      "${formatlist("arn:aws:s3:::%s/*", var.athena_data_buckets)}",
      "${formatlist("arn:aws:s3:::%s", var.athena_data_buckets)}",
    ]
  }
}

// IAM Policy Doc: Allow configured data buckets to send SQS messages
data "aws_iam_policy_document" "athena_data_bucket_sqs_sendmessage" {
  statement {
    effect = "Allow"

    actions = [
      "sqs:SendMessage",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      "${aws_sqs_queue.streamalert_athena_data_bucket_notifications.arn}",
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"

      values = [
        "${formatlist("arn:aws:s3:*:*:%s", var.athena_data_buckets)}",
      ]
    }
  }
}
