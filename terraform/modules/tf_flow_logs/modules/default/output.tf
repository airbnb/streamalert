output "cloudwatch_log_destination_arn" {
  value = "${aws_cloudwatch_log_destination.kinesis.arn}"
}
