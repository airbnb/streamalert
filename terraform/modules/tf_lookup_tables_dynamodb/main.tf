data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables_dynamodb" {
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:DescribeTable",
    ]

    resources = local.dynamodb_table_arns
  }
}

module "aws_iam_policy_module" {
  source = "../tf_lookup_tables_policy"

  policy_json = data.aws_iam_policy_document.streamalert_read_items_from_lookup_tables_dynamodb.json
  roles       = var.roles
  role_count  = var.role_count
  type        = "dynamodb"
  prefix      = var.prefix
}

locals {
  // use the list of dynamodb table names to generate a list of ARNs
  dynamodb_table_arns = formatlist(
    "arn:aws:dynamodb:%s:%s:table/%s",
    var.region,
    var.account_id,
    var.dynamodb_tables,
  )
}
