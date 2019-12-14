# StreamAlert CloudWatch Events Terraform Module
Configure the necessary resources to deliver all events published to CloudWatch Events to AWS Kinesis.

## Components
* Configures a CloudWatch Event to log all API calls to Kinesis.
* Creates an IAM Role/Policy to allow CloudWatch Events to deliver to Kinesis.

## Example
```hcl
module "cloudwatch_events" {
  source         = "./modules/tf_cloudwatch_events"
  prefix         = "company"
  cluster        = "prod"
  event_pattern  = "{"accountId": ["123456789012"]}"
  kinesis_arn    = "arn:aws:kinesis:us-east-1:123456789012:stream/company_prod_streamalert" // Output from another module
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
    <td>event_pattern</td>
    <td>Event pattern used to filter events. See: https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html#CloudWatchEventsPatterns</td>
    <td>null (not required)</td>
  </tr>
  <tr>
    <td>kinesis_arn</td>
    <td>The ARN of the Kinesis Stream to deliver CloudTrail logs</td>
    <td>None</td>
  </tr>
</table>
