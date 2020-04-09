output "data_bucket_arn" {
  value = aws_s3_bucket.streamalert_data.arn
}

output "data_bucket_name" {
  value = aws_s3_bucket.streamalert_data.bucket
}

output "firehose_role_arn" {
  value = aws_iam_role.streamalert_kinesis_firehose.arn
}
