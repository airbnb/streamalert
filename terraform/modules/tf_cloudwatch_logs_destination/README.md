# StreamAlert CloudWatch Logs Destination Terraform Module
This module creates the necessary IAM role that can be assumed by the AWS ``logs`` service from multiple regions. Since IAM is a global service, multiple IAM roles do **not** need to be created in order to support multi-region role assumption.

## Main Module

### Components
* IAM role to be assumed by the `logs` service, allowing it to write to the specified destination/Kinesis Stream from the various regions specified.

### Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>prefix</td>
    <td>The prefix for this StreamAlert deployment</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>The StreamAlert cluster with which this module is associated</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>destination_kinesis_stream_arn</td>
    <td>ARN of the Kinesis Stream to which the CloudWatch Logs should be sent</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>regions</td>
    <td>A list of regions from which the IAM role that is created should be assumable</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>

#### Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>cloudwatch_logs_subscription_role_arn</td>
    <td>The ARN of the IAM role that is capable of subscribing to the created destination(s)</td>
  </tr>
</table>

#### Example
```hcl
module "cwl_destination_role" {
  source                         = "./modules/tf_cloudwatch_logs_destination"
  prefix                         = "orgname"
  cluster                        = "prod"
  destination_kinesis_stream_arn = "arn:aws:kinesis:region:account-id:stream/stream-name"
  regions                        = ["us-east-1", "us-west-1"]
}
```

## `destination` Submodule

### Components
The `destination` submodule within `modules` can be used to create the following resources in **multiple regions**:
* A CloudWatch Log Destination to which logs will be forwarded.
* A CloudWatch Logs Destination Policy that allows other accounts to subscribe to the above destination.

Multi-region support in this submodule is made possible via aliased terraform providers. These are created in the `providers.tf` file at the root of the `terraform` directory and passed in via the `providers` meta-argument.

### Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>prefix</td>
    <td>The prefix for this StreamAlert deployment</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>The StreamAlert cluster with which this module is associated</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>destination_kinesis_stream_arn</td>
    <td>ARN of the Kinesis Stream to which the CloudWatch Logs should be sent</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>account_ids</td>
    <td>A list of AWS account IDs for which cross-account support should be enabled for this destination</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cloudwatch_logs_subscription_role_arn</td>
    <td>The ARN of the IAM role that is capable of subscribing to the created destination(s). This is an output of the above parent module</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>

#### Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>cloudwatch_logs_destination_arn</td>
    <td>The ARN of CloudWatch Logs destination that is created for use by other accounts to send data</td>
  </tr>
</table>

#### Example
```hcl
module "cwl_destination" {
  source                                = "./modules/tf_cloudwatch_logs_destination/modules/destination"
  prefix                                = "orgname"
  cluster                               = "prod"
  destination_kinesis_stream_arn        = "arn:aws:kinesis:region:account-id:stream/stream-name"
  account_ids                           = ["123456789012", "234567890123"]
  cloudwatch_logs_subscription_role_arn = ${module.cwl_destination_role.cloudwatch_logs_subscription_role_arn
  providers                             = ["aws.us-west-2"]    // Aliased to provider in terraform/providers.tf
}
```
