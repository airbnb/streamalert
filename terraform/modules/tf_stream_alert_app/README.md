# StreamAlert App Integration Terraform Module
This Terraform module creates a Lambda function that runs on a schedule for fetching logs from various services and sending them to the StreamAlert Rule Processor.

## Components
* A Python2.7 Lambda Function to perform the polling of logs on a scheduled interval
* Production alias for Lambda Function
* IAM Role, Role Policy, and Policy Document to allow for function
  * Invocation of StreamAlert Rule Processor
  * Publishing SNS messages to the dead letter queue topic
  * Getting the config, auth, and state parameters from SSM Parameter Store
  * Updating the state parameter in SSM Parameter Store
  * Creating CloudWatch log groups and streams
  * CloudWatch Event Rule invocation of app integration function
* CloudWatch Event Target for the Event Rule
* CloudWatch log retention policy

## Example
```
module "stream_alert_app" {
  account_id                   = "123456789012"
  app_config_parameter         = "{\"cluster\": \"prod\", \"prefix\": \"testprefix\", \"interval\": \"rate(1 hour)\", \"type\": \"duo_auth\", \"app_name\": \"duo-auth-app\"}"
  app_memory                   = "512"
  app_name                     = "duo-auth-app"
  app_timeout                  = "120"
  cluster                      = "prod"
  current_version              = "$LATEST"
  function_prefix              = "testprefix_prod_duo_auth_duo-auth-app"
  interval                     = "rate(1 hour)"
  log_level                    = "info"
  monitoring_sns_topic         = "stream_alert_monitoring"
  prefix                       = "testprefix"
  region                       = "us-east-1"
  source                       = "../modules/tf_stream_alert_app"
  stream_alert_apps_config     = "${var.stream_alert_apps_config}"
  type                         = "duo_auth"
}
```

## Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>account_id</td>
    <td>The AWS account ID</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>app_config_parameter</td>
    <td>JSON escaped string of config to be placed in AWS SSM Parameter Store</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>app_memory</td>
    <td>The memory allocation in MB for the Lambda function</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>app_name</td>
    <td>The name of the configured app integration</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>app_timeout</td>
    <td>The max runtime in seconds for the Lambda function</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>The name of the cluster this Lambda function will be running in</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>current_version</td>
    <td>The currently published version of the Lambda production alias</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>function_prefix</td>
    <td>The constructed prefix for this function used throughout the Terraform module as a helper</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>interval</td>
    <td>The Cloudwatch-Lambda invocation schedule expression</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>log_level</td>
    <td>The logger level to be use within the running Lambda function</td>
    <td>"info"</td>
    <td>False</td>
  </tr>
  <tr>
    <td>monitoring_sns_topic</td>
    <td>The AWS SNS topic that will be use as the Lambda's Dead Letter Queue</td>
    <td>stream_alert_monitoring</td>
    <td>True</td>
  </tr>
  <tr>
    <td>prefix</td>
    <td>The resource prefix, normally an organizational name or descriptor</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region the Lambda function will run in</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>source</td>
    <td>The Terraform source this module should use</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_alert_apps_config</td>
    <td>Map of the apps configuration loaded from conf/lambda.json. Relevant keys are listed below.</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_alert_apps_config.handler</td>
    <td>The Python function entry point</td>
    <td>"app_integrations.main.handler"</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_alert_apps_config.source_bucket</td>
    <td>The name of the S3 bucket to store Lambda deployment packages</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_alert_apps_config.source_object_key</td>
    <td>he object in S3 containing the Lambda source</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>type</td>
    <td>The type of app integration this Lambda function is for</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>

