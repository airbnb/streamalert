// User account to write to the stream
resource "aws_iam_user" "stream_alert_wo" {
  name = "${var.username}"
}

// Access keys for the write-only user
resource "aws_iam_access_key" "stream_alert_wo" {
  user = "${aws_iam_user.stream_alert_wo.name}"
}
