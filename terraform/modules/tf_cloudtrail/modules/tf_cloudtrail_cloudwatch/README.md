# StreamAlert CloudTrail Terraform Module
Configure CloudTrail to deliver AWS API calls to S3 and, optionally, CloudWatch Logs.

## Components
* Configures CloudTrail to log to an S3 bucket, and optionally to a CloudWatch Logs Group

## Example
```hcl
module "cloudtrail_to_cloudwatch" {
  source                        = "./modules/tf_cloudtrail/modules/tf_cloudtrail_cloudwatch"
  region                        = "us-east-1"
  prefix                        = "company"
  cluster                       = "prod"
  cloudwatch_destination_arn    = "arn:aws:logs:us-east-1:123456789012:destination:company_prod_streamalert_log_destination" // Output from another module
  retention_in_days             = 4
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
    <td>region</td>
    <td>AWS region where the CloudWatch Logs resources should be created</td>
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
    <td>cloudwatch_destination_arn</td>
    <td>ARN of the CloudWatch Destination to forward logs to that are sent to a CloudWatch Logs Group</td>
    <td>""</td>
  </tr>
  <tr>
    <td>retention_in_days</td>
    <td>Days for which to retain logs in the CloudWatch Logs Group</td>
    <td>1</td>
  </tr>
  <tr>
    <td>exclude_home_region_events</td>
    <td>Set to `true` to omit CloudTrail events logged in the "home" region. This is useful when global CloudTrail is desired, and a CloudWatch Logs Group is used, but home events are already collected (e.g. via another CloudTrail)</td>
    <td>false</td>
  </tr>
</table>

## Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default (None=Required)</th>
  </tr>
  <tr>
    <td>cloudtrail_to_cloudwatch_logs_role</td>
    <td>ARN of the IAM role to be used for sending logs to the CloudWatch Logs Group</td>
    <td>None</td>
  </tr>
  <tr>
    <td>cloudwatch_logs_group_arn</td>
    <td>ARN of the CloudWatch Logs Group to which CloudTrail logs should be sent</td>
    <td>None</td>
  </tr>
</table>
