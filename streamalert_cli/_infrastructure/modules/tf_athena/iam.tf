// IAM Role Policy: Allow the function read and delete SQS messages
resource "aws_iam_role_policy" "sqs_role_policy" {
  name   = "SQSReadDeleteMessages"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.sqs_role_policy.json
}

// IAM Policy Doc: decrypt, read, and delete SQS messages
data "aws_iam_policy_document" "sqs_role_policy" {
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      aws_kms_key.sse.arn,
    ]
  }

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
      aws_sqs_queue.data_bucket_notifications.arn,
    ]
  }
}

// IAM Role Policy: Allow the Lambda function to execute Athena queries and perform Glue operations
// Ref: http://amzn.to/2tSyxUV
resource "aws_iam_role_policy" "athena_glue_role_policy" {
  name   = "AthenaGlueAccess"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.athena_glue_role_policy.json
}

// IAM Policy Doc: Athena and Glue permissions
data "aws_iam_policy_document" "athena_glue_role_policy" {
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
      "glue:BatchDeletePartition",
      "glue:BatchDeleteTable",
      "glue:BatchGetPartition",
      "glue:CreateDatabase",
      "glue:CreatePartition",
      "glue:CreateTable",
      "glue:DeleteDatabase",
      "glue:DeletePartition",
      "glue:DeleteTable",
      "glue:GetDatabase",
      "glue:GetDatabases",
      "glue:GetPartition",
      "glue:GetPartitions",
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
}

// IAM Role Policy: Allow the Lambda function to read data buckets
resource "aws_iam_role_policy" "athena_results_bucket_role_policy" {
  name   = "S3ResultsBucket"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.athena_results_bucket_role_policy.json
}

// IAM Policy Doc: Allow Athena to read data from configured buckets
//                 This is necessary for table repairs
data "aws_iam_policy_document" "athena_results_bucket_role_policy" {
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
      "arn:aws:s3:::${var.results_bucket}*",
    ]
  }
}

// IAM Role Policy: Allow the Lambda function to read data buckets
resource "aws_iam_role_policy" "data_bucket_role_policy" {
  name   = "S3DataBucket"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.data_bucket_role_policy.json
}

// IAM Policy Doc: Allow Athena to read data from configured buckets
//                 This is necessary for table repairs
data "aws_iam_policy_document" "data_bucket_role_policy" {
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

    resources = concat(
      formatlist("arn:aws:s3:::%s/*", var.athena_data_buckets),
      formatlist("arn:aws:s3:::%s", var.athena_data_buckets),
    )
  }
}

// IAM Policy Doc: Allow configured data buckets to send SQS messages
data "aws_iam_policy_document" "data_bucket_sqs" {
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
      aws_sqs_queue.data_bucket_notifications.arn,
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"

      values = formatlist("arn:aws:s3:*:*:%s", var.athena_data_buckets)
    }
  }
}
