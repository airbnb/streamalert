output "data_bucket_arn" {
  value = "${aws_s3_bucket.stream_alert_data.arn}"
}

output "firehose_role_arn" {
  value = "${aws_iam_role.stream_alert_kinesis_firehose.arn}"
}
