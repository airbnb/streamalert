data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables" {
  statement {
    actions   = [
      "dynamodb:GetItem",
      "dynamodb:DescribeTable"
    ]
    resources = "${local.dynamodb_table_arns}"
  }

  statement {
    actions   = ["s3:List*"]
    resources = "${local.s3_bucket_arns}"
  }

  statement {
    actions   = ["s3:Get*"]
    resources = "${local.s3_bucket_arn_star}"
  }
}


resource "aws_iam_policy" "streamalert_read_from_lookup_tables_policy" {
  name   = "StreamAlertReadFromLookupTablesPolicy"
  policy = "${data.aws_iam_policy_document.streamalert_read_items_from_lookup_tables.json}"
}

resource "aws_iam_role_policy_attachment" "streamalert_read_from_lookup_tables" {
  count      = "${length(var.roles)}"
  role       = "${element(var.roles, count.index)}"
  policy_arn = "${aws_iam_policy.streamalert_read_from_lookup_tables_policy.arn}"
}

locals {
  s3_bucket_arns = "${formatlist("arn:aws:s3:::%s", var.s3_buckets)}"
  s3_bucket_arn_star = "${formatlist("arn:aws:s3:::%s/*", var.s3_buckets)}"

  dynamodb_table_arns = "${formatlist("arn:aws:dynamodb:%s:%s:table/%s", var.region, var.account_id, var.dynamodb_tables)}"
}