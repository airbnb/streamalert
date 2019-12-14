# StreamAlert CloudTrail Terraform Module
Configure CloudTrail to deliver AWS API calls to S3 and, optionally, CloudWatch Logs.

## Components
* Configures CloudTrail to log to an S3 bucket, and optionally to a CloudWatch Logs Group

## Example
```hcl
module "cloudtrail" {
  source                        = "./modules/tf_cloudtrail"
  primary_account_id            = "123456789012"
  region                        = "us-east-1"
  prefix                        = "company"
  cluster                       = "prod"
  s3_cross_account_ids          = ["456789012345"]
  enable_logging                = true
  is_global_trail               = true
  s3_logging_bucket             = "logging-bucket-name"
  s3_bucket_name                = "cloudtrail-bucket-name"
  s3_event_selector_type        = "All"
  cloudwatch_logs_role_arn      = "arn:aws:iam::123456789012:role/streamalert/company_prod_cloudwatch_logs_subscription_role" // Output from another module
  cloudwatch_logs_group_arn     = "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup"                  // Output from another module
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
    <td>AWS region where the CloudTrail resources should be created</td>
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
    <td>is_global_trail</td>
    <td>Log API calls from all AWS regions</td>
    <td>true</td>
  </tr>
  <tr>
    <td>s3_logging_bucket</td>
    <td>Name of bucket where S3 logs should be sent</td>
    <td>None</td>
  </tr>
  <tr>
    <td>s3_bucket_name</td>
    <td>Name to apply to the bucket used for storing CloudTrail logs</td>
    <td>None</td>
  </tr>
  <tr>
    <td>s3_event_selector_type</td>
    <td>Type of S3 object level logging to enable via CloudTrail. Choices are: "ReadOnly", "WriteOnly", "All", or "", where "" disables this feature</td>
    <td>""</td>
  </tr>
  <tr>
    <td>cloudwatch_logs_role_arn</td>
    <td>ARN of the IAM role to be used for sending logs to the CloudWatch Logs Group</td>
    <td>false</td>
  </tr>
  <tr>
    <td>cloudwatch_logs_group_arn</td>
    <td>ARN of the CloudWatch Logs Group to which CloudTrail logs should be sent</td>
    <td>false</td>
  </tr>
</table>
