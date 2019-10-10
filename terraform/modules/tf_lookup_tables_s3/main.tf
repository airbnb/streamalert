data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables_s3" {
  statement {
    actions = ["s3:List*"]
    # TF-UPGRADE-TODO: In Terraform v0.10 and earlier, it was sometimes necessary to
    # force an interpolation expression to be interpreted as a list by wrapping it
    # in an extra set of list brackets. That form was supported for compatibility in
    # v0.11, but is no longer supported in Terraform v0.12.
    #
    # If the expression in the following list itself returns a list, remove the
    # brackets to avoid interpretation as a list of lists. If the expression
    # returns a single list item then leave it as-is and remove this TODO comment.
    resources = [local.s3_bucket_arns]
  }

  statement {
    actions = ["s3:Get*"]
    # TF-UPGRADE-TODO: In Terraform v0.10 and earlier, it was sometimes necessary to
    # force an interpolation expression to be interpreted as a list by wrapping it
    # in an extra set of list brackets. That form was supported for compatibility in
    # v0.11, but is no longer supported in Terraform v0.12.
    #
    # If the expression in the following list itself returns a list, remove the
    # brackets to avoid interpretation as a list of lists. If the expression
    # returns a single list item then leave it as-is and remove this TODO comment.
    resources = [local.s3_bucket_arn_star]
  }
}

module "aws_iam_policy_module" {
  source      = "../tf_lookup_tables_policy"
  policy_json = data.aws_iam_policy_document.streamalert_read_items_from_lookup_tables_s3.json
  roles       = var.roles
  role_count  = var.role_count
  type        = "s3"
  prefix      = var.prefix
}

locals {
  # Generate a list of S3 bucket ARNs
  s3_bucket_arns = formatlist("arn:aws:s3:::%s", var.s3_buckets)

  # Generate a list of S3 bucket ARNs, plus asterisk at the end to match any object in the bucket
  s3_bucket_arn_star = formatlist("arn:aws:s3:::%s/*", var.s3_buckets)
}

