# Stream Alert Flow Log Terraform Module
* StreamAlert: a serverless, real-time intrusion detection engine.
* This Terraform module enables flow logs for specified VPCs, subnets, and ENIs
the specified kinesis stream, and the necessary IAM roles for everything to work

## Components
Creates the following:
* A cloudwatch log group for the flow logs
* A subscription filter delivering the logs to the specified destination stream
* Enables flow logs for VPC resources specified in `var.targets`


## Example
```
module "flow_logs_prod" {
  source                 = "modules/tf_stream_alert_flow_logs"
  destination_stream_arn = "${module.kinesis_prod.arn}"
  targets                = "${var.flow_log_settings["prod"]}"
  region                 = "${lookup(var.clusters, "prod")}"
  flow_log_group_name    = "${var.prefix}_prod_stream_alert_flow_logs"
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
    <td>ARN of the kinesis stream that will receive the flow logs</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region for your cluster</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>targets</td>
    <td>Map of "enis", "vpcs", and "subnets", each an array containing IDs of resources to enable flow logs for</td>
    <td>{"vpcs":[], "subnets":[], "enis":[]}</td>
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
