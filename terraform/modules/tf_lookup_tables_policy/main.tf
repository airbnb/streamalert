resource "aws_iam_policy" "streamalert_read_from_lookup_tables" {
  name   = "${var.prefix}_StreamAlertReadFromLookupTablesPolicy_${var.type}"
  policy = var.policy_json
}

resource "aws_iam_role_policy_attachment" "streamalert_read_from_lookup_tables" {
  count      = var.role_count
  role       = element(var.roles, count.index)
  policy_arn = aws_iam_policy.streamalert_read_from_lookup_tables.arn
}
