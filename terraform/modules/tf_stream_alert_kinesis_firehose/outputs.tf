output "data_bucket_arn" {
  value = "${aws_s3_bucket.stream_alert_data.arn}"
}
