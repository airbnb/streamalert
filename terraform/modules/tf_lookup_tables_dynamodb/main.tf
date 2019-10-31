data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables_dynamodb" {
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:DescribeTable",
    ]

    # TF-UPGRADE-TODO: In Terraform v0.10 and earlier, it was sometimes necessary to
    # force an interpolation expression to be interpreted as a list by wrapping it
    # in an extra set of list brackets. That form was supported for compatibility in
    # v0.11, but is no longer supported in Terraform v0.12.
    #
    # If the expression in the following list itself returns a list, remove the
    # brackets to avoid interpretation as a list of lists. If the expression
    # returns a single list item then leave it as-is and remove this TODO comment.
    resources = [local.dynamodb_table_arns]
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
