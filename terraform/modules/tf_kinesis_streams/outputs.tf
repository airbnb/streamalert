output "arn" {
  value = "${aws_kinesis_stream.stream_alert_stream.arn}"
}

output "username" {
  value = "${aws_iam_access_key.stream_alert.*.user}"
}

output "access_key_id" {
  value = "${aws_iam_access_key.stream_alert.*.id}"
}

output "secret_key" {
  value = "${aws_iam_access_key.stream_alert.*.secret}"
}
