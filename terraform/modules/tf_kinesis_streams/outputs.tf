output "arn" {
  value = aws_kinesis_stream.streamalert_stream.arn
}

output "stream_name" {
  value = "${aws_kinesis_stream.streamalert_stream.name}"
}

output "username" {
  value = aws_iam_user.streamalert.*.name
}

output "user_arn" {
  value = aws_iam_user.streamalert.*.arn
}

output "access_key_id" {
  value = aws_iam_access_key.streamalert.*.id
}

output "secret_key" {
  value = aws_iam_access_key.streamalert.*.secret
}
