# Stream Alert CloudTrail Terraform Module
Configure CloudTrail to deliver AWS API calls to AWS Kinesis and Amazon S3.

## Components
* Configures CloudTrail to log into an S3 bucket.
* Configures a CloudWatch Event to log all API calls to Kinesis.
* Creates an IAM Role/Policy to allow CloudWatch Events to deliver to Kinesis.

## Example
For users with no existing CloudTrail:
```
module "cloudtrail" {
  source         = "modules/tf_stream_alert_cloudtrail"
  prefix         = "streamalert"
  cluster        = "prod"
  enable_logging = true
  account_id     = "111111111112"
  kinesis_arn    = "arn:aws:kinesis:region:account-id:stream/stream-name"
}
```

To skip the creation of a CloudTrail, set the `existing_trail` option to `true`:
```
module "cloudtrail" {
  source         = "modules/tf_stream_alert_cloudtrail"
  prefix         = "streamalert"
  cluster        = "prod"
  enable_logging = true
  existing_trail = true
  account_id     = "111111111112"
  kinesis_arn    = "arn:aws:kinesis:region:account-id:stream/stream-name"
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
    <td>prefix</td>
    <td>Resource prefix namespace</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>Name of the cluster</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>enable_logging</td>
    <td>Enables logging for the CloudTrail</td>
    <td>true</td>
    <td>False</td>
  </tr>
  <tr>
    <td>existing_trail</td>
    <td>Do you have an existing CloudTrail?</td>
    <td>false</td>
    <td>False</td>
  </tr>
  <tr>
    <td>is_global_trail</td>
    <td>Log API calls from all AWS regions</td>
    <td>true</td>
    <td>False</td>
  </tr>
  <tr>
    <td>account_id</td>
    <td>AWS account ID</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>kinesis_arn</td>
    <td>The ARN of the Kinesis Stream to deliver CloudTrail logs</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>
