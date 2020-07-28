// CloudWatch Event Permission for Individual AWS Accounts
resource "aws_cloudwatch_event_permission" "account_access" {
  count        = length(var.accounts)
  principal    = element(var.accounts, count.index)
  statement_id = "account_${element(var.accounts, count.index)}_${var.region}"
}

// CloudWatch Event Permission for AWS Orgs
resource "aws_cloudwatch_event_permission" "organization_access" {
  count        = length(var.organizations)
  principal    = "*"
  statement_id = "organization_${element(var.organizations, count.index)}_${var.region}"

  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = element(var.organizations, count.index)
  }
}
