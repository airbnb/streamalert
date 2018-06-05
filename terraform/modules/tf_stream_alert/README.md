# StreamAlert Terraform Module
This Terraform module creates the rule processor and its associated components:

* CloudWatch log group, metric alarms, and metric filters
* IAM role and policies
* Lambda alias: "production"
* SNS topic subscriptions

## Example
```
module "stream_alert" {
  source                       = "../modules/tf_stream_alert"
  account_id                   = "112233445566"
  region                       = "us-east-1"
  lambda_function_prod_version = "$LATEST"
  lambda_handler               = "main.lambda_handler"
}
```
