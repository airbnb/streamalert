resource "aws_sns_topic" "streamalert" {
  name         = "${var.lambda_function_name}_monitoring"
  display_name = "${var.lambda_function_name}_monitoring"
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = "${aws_sns_topic.streamalert.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.stream_alert_output_processor.arn}"
}

resource "aws_lambda_function" "stream_alert_output_processor" {
  runtime       = "python2.7"
  handler       = "main.handler"
  description   = "StreamAlert Output Processor"
  function_name = "${var.output_lambda_function_name}"
  role          = "${aws_iam_role.stream_alert_output_lambda_role.arn}"
  memory_size   = "${var.output_lambda_memory}"
  timeout       = "${var.output_lambda_timeout}"
  s3_bucket     = "${var.lambda_source_bucket_name}"
  s3_key        = "${var.output_lambda_source_key}"
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.stream_alert_output_processor.arn}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.streamalert.arn}"
}

resource "aws_s3_bucket" "stream_alert_output" {
  bucket        = "${replace(var.output_lambda_function_name, "_", ".")}.results"
  acl           = "private"
  force_destroy = true
}
