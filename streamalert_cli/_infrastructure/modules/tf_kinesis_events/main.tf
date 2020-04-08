// AWS Lambda Function Policy
resource "aws_iam_role_policy" "streamalert_lambda_kinesis" {
  name   = "KinesisGetRecords"
  role   = var.lambda_role_id
  policy = data.aws_iam_policy_document.kinesis_read.json
}

// IAM Policy Doc: List and Get records from Kinesis
data "aws_iam_policy_document" "kinesis_read" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:ListStreams",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "kinesis:DescribeStream",
      "kinesis:GetRecords",
      "kinesis:GetShardIterator",
    ]

    resources = [var.kinesis_stream_arn]
  }
}

resource "aws_lambda_event_source_mapping" "streamalert_kinesis_production_event_mapping" {
  enabled           = var.lambda_production_enabled
  batch_size        = var.batch_size
  event_source_arn  = var.kinesis_stream_arn
  function_name     = var.lambda_function_alias_arn
  starting_position = "TRIM_HORIZON"
}
