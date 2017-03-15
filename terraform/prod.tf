// StreamAlert Lambda Function
module "stream_alert_prod" {
  source                        = "modules/tf_stream_alert"
  account_id                    = "${lookup(var.account, "aws_account_id")}"
  region                        = "${lookup(var.clusters, "prod")}"
  prefix                        = "${lookup(var.account, "prefix")}"
  cluster                       = "prod"
  kms_key_arn                   = "${aws_kms_key.stream_alert_secrets.arn}"

  rule_processor_config         = "${var.rule_processor_config}"
  rule_processor_lambda_config  = "${lookup(var.rule_processor_lambda_config, "prod")}"
  rule_processor_prod_version   = "${lookup(var.rule_processor_versions, "prod")}"

  alert_processor_config        = "${var.alert_processor_config}"
  alert_processor_lambda_config = "${lookup(var.alert_processor_lambda_config, "prod")}"
  alert_processor_prod_version  = "${lookup(var.alert_processor_versions, "prod")}"
}

// Cloudwatch alerts for production Lambda functions
module "cloudwatch_monitoring_prod" {
  source           = "modules/tf_stream_alert_monitoring"
  sns_topic_arns   = ["${module.stream_alert_prod.sns_topic_arn}"]
  lambda_functions = [
    "${lookup(var.account, "prefix")}_prod_streamalert_rule_processor",
    "${lookup(var.account, "prefix")}_prod_streamalert_alert_processor"
  ]
}

// Kinesis Stream and Firehose to send data to the Lambda function
module "kinesis_prod" {
  source                  = "modules/tf_stream_alert_kinesis"
  account_id              = "${lookup(var.account, "aws_account_id")}"
  region                  = "${lookup(var.clusters, "prod")}"
  cluster_name            = "prod"
  firehose_s3_bucket_name = "${lookup(var.account, "prefix")}.prod.${lookup(var.firehose, "s3_bucket_suffix")}"
  stream_name             = "${lookup(var.account, "prefix")}_prod_stream_alert_kinesis"
  firehose_name           = "${lookup(var.account, "prefix")}_prod_stream_alert_firehose"
  username                = "${lookup(var.account, "prefix")}_prod_stream_alert_user"
  stream_config           = "${lookup(var.kinesis_streams_config, "prod")}"
}

// Enable a Kinesis Stream to send events to Lambda
module "kinesis_events_prod" {
  source                    = "modules/tf_stream_alert_kinesis_events"
  lambda_production_enabled = true
  lambda_role_id            = "${module.stream_alert_prod.lambda_role_id}"
  lambda_function_arn       = "${module.stream_alert_prod.lambda_arn}"
  kinesis_stream_arn        = "${module.kinesis_prod.arn}"
  role_policy_prefix        = "prod"
}


output "kinesis_prod_username" {
  value = "${module.kinesis_prod.username}"
}

output "kinesis_prod_access_key_id" {
  value = "${module.kinesis_prod.access_key_id}"
}

output "kinesis_prod_secret_key" {
  value = "${module.kinesis_prod.secret_key}"
}