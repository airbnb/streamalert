output "arn" {
  value = "${aws_kinesis_stream.stream_alert_stream.arn}"
}

output "username" {
  value = "${aws_iam_user.stream_alert_wo.name}"
}

output "access_key_id" {
  value = "${aws_iam_access_key.stream_alert_wo.id}"
}

output "secret_key" {
  value = "${aws_iam_access_key.stream_alert_wo.secret}"
}

output "bucket_arn" {
  value = "${aws_s3_bucket.firehose_store.arn}"
}
