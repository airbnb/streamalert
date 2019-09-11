resource "aws_iam_policy" "streamalert_read_from_lookup_tables" {
  name   = "StreamAlertReadFromLookupTablesPolicy_${var.type}"
  policy = "${var.policy_json}"
}

resource "aws_iam_role_policy_attachment" "streamalert_read_from_lookup_tables_s3" {
  count      = "${length(var.roles)}"
  role       = "${element(var.roles, count.index)}"
  policy_arn = "${aws_iam_policy.streamalert_read_from_lookup_tables.arn}"
}
