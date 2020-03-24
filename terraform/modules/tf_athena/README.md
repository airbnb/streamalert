# StreamAlert Athena Terraform Module
This Terraform module creates a Lambda function for refreshing Athena Partitions once new data is written to S3

## Components
* A Python3.7 Lambda Function to perform a table refresh
* IAM Role and Policy to allow for Athena execution
* S3 bucket notifications
* Lambda permissions

## Example
```
module "streamalert_athena" {
  source                       = "../modules/tf_athena"
  lambda_s3_bucket             = "my-source-bucket"
  lambda_s3_key                = "source/athena_partition_refresh_code.zip"
  athena_data_buckets          = ["my-org-streamalerts"]
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
    <td>lambda_handler</td>
    <td>The Python function entry point</td>
    <td>"main.handler"</td>
    <td>False</td>
  </tr>
  <tr>
    <td>lambda_timeout</td>
    <td>The max runtime in seconds for the Lambda function</td>
    <td>60 seconds</td>
    <td>False</td>
  </tr>
  <tr>
    <td>lambda_memory</td>
    <td>The memory allocation in MB for the Lambda function</td>
    <td>128MB</td>
    <td>False</td>
  </tr>
  <tr>
    <td>lambda_s3_bucket</td>
    <td>The name of the S3 bucket to store Lambda deployment packages</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_s3_key</td>
    <td>The object in S3 containing the Lambda source</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_log_level</td>
    <td>The current log level of the Lambda function</td>
    <td>info</td>
    <td>False</td>
  </tr>
  <tr>
    <td>current_version</td>
    <td>The currently published version of the Lambda production alias</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>athean_data_buckets</td>
    <td>A list of buckets to monitor changes to for Hive partitioning</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>prefix</td>
    <td>The resource prefix, normally an organizational name or descriptor</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>schedule_expression</td>
    <td>The Cloudwatch-Lambda invocation schedule expression</td>
    <td>rate(10 minutes)</td>
    <td>False</td>
  </tr>
</table>
