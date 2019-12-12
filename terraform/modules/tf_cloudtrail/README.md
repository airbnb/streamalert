# StreamAlert CloudTrail Terraform Module
Configure CloudTrail to deliver AWS API calls to S3 and, optionally, CloudWatch Logs.

## Components
* Configures CloudTrail to log to an S3 bucket, and optionally to a CloudWatch Logs Group

## Example
For users with no existing CloudTrail:
```hcl
module "cloudtrail" {
  source                        = "modules/tf_cloudtrail"
  primary_account_id            = "123456789012"
  region                        = "us-east-1"
  prefix                        = "company"
  cluster                       = "prod"
  s3_cross_account_ids          = ["456789012345"]
  enable_logging                = true
  retention_in_days             = 4
  is_global_trail               = true
  s3_logging_bucket             = "logging-bucket-name"
  s3_bucket_name                = "cloudtrail-bucket-name"
  s3_event_selector_type        = "All"
  send_to_cloudwatch            = true
  cloudwatch_destination_arn    = "arn:aws:logs:us-east-1:123456789012:destination:company_prod_streamalert_log_destination" // Output from another module
  exclude_home_region_events    = true
}
```

## Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default (None=Required)</th>
  </tr>
  <tr>
    <td>primary_account_id</td>
    <td>ID of the deployment account</td>
    <td>None</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region within which the CloudTrail resources should be created</td>
    <td>None</td>
  </tr>
  <tr>
    <td>prefix</td>
    <td>Resource prefix namespace</td>
    <td>None</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>Name of the cluster</td>
    <td>None</td>
  </tr>
  <tr>
    <td>s3_cross_account_ids</td>
    <td>List of external account IDs for which logging should be allowed to the S3 bucket</td>
    <td>[]</td>
  </tr>
  <tr>
    <td>enable_logging</td>
    <td>Enables logging for the CloudTrail. Setting this to false will pause logging on the trail</td>
    <td>true</td>
  </tr>
  <tr>
    <td>retention_in_days</td>
    <td>Days for which to retain logs in the CloudWatch Logs Group. Default=1</td>
    <td>1</td>
  </tr>
  <tr>
    <td>is_global_trail</td>
    <td>Log API calls from all AWS regions</td>
    <td>true</td>
  </tr>
  <tr>
    <td>s3_logging_bucket</td>
    <td>Name of bucket where s3 logs should be sent</td>
    <td>None</td>
  </tr>
  <tr>
    <td>s3_bucket_name</td>
    <td>Name to apply to the bucket used for CloudTrail logs</td>
    <td>None</td>
  </tr>
  <tr>
    <td>s3_event_selector_type</td>
    <td>Type of S3 object level logging to enable via CloudTrail. Choices are: "ReadOnly", "WriteOnly", "All", or "" where "" disables this feature</td>
    <td>""</td>
  </tr>
  <tr>
    <td>send_to_cloudwatch</td>
    <td>Set to `true` to enable sending CloudTrail logs to a CloudWatch Logs Group</td>
    <td>false</td>
  </tr>
  <tr>
    <td>cloudwatch_destination_arn</td>
    <td>ARN of the CloudWatch Destination to which the logs that are sent to a CloudWatch Logs Group will be forwarded. Only required if `send_to_cloudwatch` is set to `true`</td>
    <td>""</td>
  </tr>
  <tr>
    <td>exclude_home_region_events</td>
    <td>Set to `true` to omit CloudTrail events logged in the "home" region. This is useful when global CloudTrail is desired, and a CloudWatch Logs Group is used, but home events are already collected (e.g. via another CloudTrail)</td>
    <td>false</td>
  </tr>
</table>
