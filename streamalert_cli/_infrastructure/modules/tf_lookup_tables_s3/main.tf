data "aws_iam_policy_document" "streamalert_read_items_from_lookup_tables_s3" {
  statement {
    actions = ["s3:List*"]
    resources = local.s3_bucket_arns
  }

  statement {
    actions = ["s3:Get*"]
    resources = local.s3_bucket_arn_star
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
