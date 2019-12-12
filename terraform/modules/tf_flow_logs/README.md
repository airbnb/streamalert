# StreamAlert VPC Flow Log Terraform Module
This module will create Flow Logs for specified VPCs, Subnets, and ENIs.
Additionally, it creates resources for sending VPC Flow Logs to an AWS Kinesis Stream,
via a CloudWatch Logs Subscription Filter and a CloudWatch Logs Destination.

#### Components
* A CloudWatch Log Group to store the Flow Logs.
* A CloudWatch Logs Subscription Filter that will deliver logs to the specified CloudWatch Logs Destination.
* Enables Flow Logs for resources specified in the `vpcs`, `subnets`, and `enis` variables.
* IAM Role and Policy to allow Flow Logs to be delivered to the CloudWatch Logs Group.

#### Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region of your VPC(s), Subnet(s), or ENI(s)</td>
    <td>us-east-1</td>
    <td>True</td>
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
    <td>cloudwatch_logs_destination_arn</td>
    <td>The ARN of the CloudWatch Logs Destination that will receive Flow Logs</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>vpcs</td>
    <td>List of AWS VPC IDs to enable flow logs for</td>
    <td>[]</td>
    <td>False</td>
  </tr>
  <tr>
    <td>subnets</td>
    <td>List of AWS VPC Subnet IDs to enable flow logs for</td>
    <td>[]</td>
    <td>False</td>
  </tr>
  <tr>
    <td>enis</td>
    <td>List of AWS VPC ENI IDs to enable flow logs for</td>
    <td>[]</td>
    <td>False</td>
  </tr>
  <tr>
    <td>log_retention</td>
    <td>The days for which the CloudWatch Log Group should retain logs</td>
    <td>7</td>
    <td>False</td>
  </tr>
  <tr>
    <td>flow_log_filter</td>
    <td>CloudWatch Subscription Filter to match flow logs</td>
    <td>"[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"</td>
    <td>False</td>
  </tr>
</table>

#### Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>cloudwatch_log_group</td>
    <td>The ARN of the CloudWatch Log Group to which Flow Log events will be published</td>
  </tr>
</table>

#### Example
```hcl
module "flow_logs_prod" {
  source                          = "./modules/tf_flow_logs"
  region                          = "us-east-1"
  prefix                          = "orgname"
  cluster                         = "prod"
  cloudwatch_logs_destination_arn = "${module.cloudwatch_destinations_prod_us-east-1.cloudwatch_logs_destination_arn}"  // Output from tf_cloudwatch_logs_destination module
  vpcs                            = ["vpc-id-01"]
}
```
