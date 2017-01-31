// Lambda function: Stream Alert Processor
//    Matches rules against logs from Kinesis Streams or S3
resource "aws_lambda_function" "stream_alert_processor" {
  function_name = "${var.lambda_function_name}"
  runtime       = "python2.7"
  description   = "StreamAlert Rule Processor"
  memory_size   = "${var.lambda_memory}"
  timeout       = "${var.lambda_timeout}"
  role          = "${aws_iam_role.stream_alert_lambda_role.arn}"
  handler       = "${var.lambda_handler}"
  s3_bucket     = "${var.lambda_source_bucket_name}"
  s3_key        = "${var.lambda_source_key}"
}

// Lambda Staging Alias: Processes alerts and logs to Cloudwatch
resource "aws_lambda_alias" "staging" {
  name             = "staging"
  description      = "staging stream_alert processor function"
  function_name    = "${aws_lambda_function.stream_alert_processor.arn}"
  function_version = "$LATEST"
}

// Lambda Production Alias: Processes alerts and sends to rule outputs
resource "aws_lambda_alias" "production" {
  name             = "production"
  description      = "production stream_alert processor function"
  function_name    = "${aws_lambda_function.stream_alert_processor.arn}"
  function_version = "${var.lambda_function_prod_version}"
}
