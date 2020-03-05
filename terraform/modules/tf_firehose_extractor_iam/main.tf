// Allow the Alert Merger to query and update the alerts table
resource "aws_iam_role_policy" "put_artifacts_firehose" {
  name   = "PutRecordsToArtifactsFirehose"
  role   = var.role_id
  policy = data.aws_iam_policy_document.put_artifacts_firehose_policy.json
}

data "aws_iam_policy_document" "put_artifacts_firehose_policy" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:DeleteDeliveryStream",
      "firehose:PutRecord",
      "firehose:PutRecordBatch",
      "firehose:UpdateDestination"
    ]

    resources = [
      var.artifact_firehose_arn
    ]
  }
}
