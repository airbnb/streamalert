data "aws_iam_policy_document" "streamalert_read_objects_from_lookup_tables_s3" {
  statement {
    actions   = ["s3:List*"]
    resources = "${local.s3_bucket_arns}"
  }

  statement {
    actions   = ["s3:Get*"]
    resources = "${local.s3_bucket_arn_star}"
  }
}

data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables_dynamodb" {
  statement {
    actions   = [
      "dynamodb:GetItem",
      "dynamodb:DescribedTable"
    ]
    resources = "${local.dynamodb_table_arns}"
  }
}


resource "aws_iam_policy" "streamalert_read_from_lookup_tables_policy" {
  name   = "StreamAlertReadFromLookupTablesPolicy"
  policy = "${data.aws_iam_policy_document.streamalert_read_items_from_lookup_tables_dynamodb.json}"
}

resource "aws_iam_policy_attachment" "streamalert_read_from_lookup_tables" {
  name       = "StreamAlertPermissionReadFromLookupTAbles"
  roles      = "${local.lambda_roles}"
  policy_arn = "${aws_iam_policy.streamalert_read_from_lookup_tables_policy.arn}"
}

locals {
  lambda_roles = [
    "airbnb_streamalert_rules_engine_role",
    "airbnb_streamalert_alert_processor_role",
    "airbnb_streamalert_classifier_*_role",
  ]

  s3_bucket_arns = "${formatlist("arn:aws:s3:::%s", var.s3_buckets)}"
  s3_bucket_arn_star = "${formatlist("arn:aws:s3:::%s/*", var.s3_buckets)}"

  dynamodb_table_arns = "${formatlist("arn:aws:dynamodb:%s:%s:%s", var.account_id, var.region, var.dynamodb_tables)}"
}