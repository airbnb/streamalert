# Stream Alert VPC Flow Log Terraform Module
* This Terraform module enables network flow logs for specified AWS VPCs, Subnets, and ENIs to send to a specified AWS Kinesis Stream.

## Components
Creates the following:
* A CloudWatch log group to store the flow logs.
* A subscription filter delivering the logs to the specified destination Kinesis Stream.
* Enables flow logs for VPC resources specified in `var.targets`.
* IAM Roles and Policies to allow flow logs to be delivered.


## Example
```

module "flow_logs_prod" {
  source                 = "modules/tf_stream_alert_flow_logs"
  flow_log_group_name    = "prefix_cluster_streamalert_flow_logs"
  destination_stream_arn = "arn:aws:kinesis:region:account-id:stream/stream-name"
  vpcs                   = ["vpc"]
  region                 = "us-east-1"
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
    <td>destination_stream_arn</td>
    <td>ARN of the Kinesis Stream which receives the flow logs</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region of your VPC(s), Subnet(s), or ENI(s)</td>
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
    <td>flow_log_group_name</td>
    <td>The name of the CloudWatch log group created to receive flow logs</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>flow_log_filter</td>
    <td>CloudWatch subscription filter to match flow logs</td>
    <td>"[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"</td>
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
    <td>cloudwatch_log_group</td>
    <td>The ARN of the StreamAlert flow log Cloudwatch Log Group</td>
  </tr>
</table>
