# Stream Alert Terraform Module
* StreamAlert: a serverless, real-time intrusion detection engine.
* This Terraform module creates the lambda function to match rules against logs.

## Components
Creates the following:
* A S3 bucket for stream_alert lambda source code.
* The Lambda function with the execution role.
* A staging and production alias.
* An SNS topic to send alerts to.

## Example
```
module "stream_alert" {
  source                       = "../modules/tf_stream_alert"
  account_id                   = "112233445566"
  region                       = "us-east-1"
  lambda_source_bucket_name    = "mycompany.streamalert.source"
  lambda_source_key            = "/source/stream_alert_v1.0"
  lambda_function_prod_version = "$LATEST"
  lambda_handler               = "main.lambda_handler"
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
    <td>Your AWS Account ID</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region for your stream</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_source_bucket_name</td>
    <td>The name of the S3 bucket to store lambda deployment packages</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_function_name</td>
    <td>The name of the stream alert lambda function</td>
    <td>stream_alert_processor</td>
    <td>False</td>
  </tr>
  <tr>
    <td>lambda_timeout</td>
    <td>The max runtime in seconds for the lambda function</td>
    <td>10</td>
    <td>False</td>
  </tr>
  <tr>
    <td>lambda_memory</td>
    <td>The memory allocation in MB for the lambda function</td>
    <td>/aws/kinesisfirehose/stream_alert</td>
    <td>False</td>
  </tr>
</table>

## Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>lambda_arn</td>
    <td>The ARN of the StreamAlert lambda function</td>
  </tr>
  <tr>
    <td>lambda_role_id</td>
    <td>The ID of the StreamAlert IAM execution role</td>
  </tr>
  <tr>
    <td>lambda_role_arn</td>
    <td>The ARN of the StreamAlert IAM execution role</td>
  </tr>
  <tr>
    <td>sns_topic_arn</td>
    <td>The ARN of the SNS topic for operational monitoring</td>
  </tr>
</table>
