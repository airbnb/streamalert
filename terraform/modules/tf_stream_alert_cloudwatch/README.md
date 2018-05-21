# StreamAlert CloudWatch Logs Cross-Account Terraform Module
* This Terraform module enables cross-account collection of CloudWatch Logs, via a CloudWatch Logs destination in each region.
* This module leverages the [concepts found here.]('https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CrossAccountSubscriptions.html')

## Components
Creates the following in _each region_:
* IAM role that will grant CloudWatch Logs the permission to put data into your Kinesis stream.
* Permissions policy to define which actions CloudWatch Logs can perform.
  * `kinesis:PutRecord` for the Kinesis stream
  * `iam:PassRole` for the previously created IAM role
* A CloudWatch Log destination that points to the cluster's default Kinesis stream.
* Policy that defines who has write access to the destination
  * `logs:PutSubscriptionFilter` for the cross-account principals (account IDs)


## Example
```
module "cloudwatch_prod_us-west-1" {
  source                 = "modules/tf_stream_alert_cloudwatch"
  cluster                = "prod"
  kinesis_stream_arn     = "${module.kinesis_advanced.arn}"
  cross_account_ids      = ["123456789012", "12345678910"]
  region                 = "us-west-1"
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
    <td>cluster</td>
    <td>Name of the cluster</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>kinesis_stream_arn</td>
    <td>ARN of the Kinesis Stream which receives the CloudWatch Logs. Output from the tf_stream_alert_kinesis_streams module</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cross_account_ids</td>
    <td>List of AWS Account IDs for which to enable cross-account log collection</td>
    <td>[]</td>
    <td>False</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region of your VPC(s), Subnet(s), or ENI(s)</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>
