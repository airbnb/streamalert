output "arn" {
  value = "${aws_kinesis_stream.streamalert_stream.arn}"
}

output "username" {
  value = "${aws_iam_access_key.streamalert.*.user}"
}

output "access_key_id" {
  value = "${aws_iam_access_key.streamalert.*.id}"
}

output "secret_key" {
  value = "${aws_iam_access_key.streamalert.*.secret}"
}
