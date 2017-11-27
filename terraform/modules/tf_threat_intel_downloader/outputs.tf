output "lambda_arn" {
  value = "${aws_lambda_function.threat_intel_downloader.arn}"
}
