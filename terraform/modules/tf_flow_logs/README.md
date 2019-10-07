# StreamAlert VPC Flow Log Terraform Submodules
This folder provides two Terraform modules to enable ingestion of VPC Flow Logs.
One module enables the 'default' resources needed to ingest these logs, both from the 'local' account
or in a cross-account setup. The 'internal' module can additionally create Flow Logs for specified VPCs, Subnets, and ENIs.
The end result will allow for sending VPC Flow Logs to the specified AWS Kinesis Stream,
[via a CloudWatch Logs Subscription Filter](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CrossAccountSubscriptions.html).

## Submodules
This folder contains the following two submodules: `defualt` and `internal`

### `default` Submodule
The `default` submodule creates the default resources necessary to enable either local or
cross-account VPC Flow Log delivery.

#### Components for `default` Submodule
* A CloudWatch Log Destination to which logs will be forwarded.
* A CloudWatch Logs Destination Policy that allows other accounts to subscribe to the above destination.
* IAM Role to be assumed by the `logs` service, allowing it to write to the specified destination/Kinesis Stream.

#### Inputs for `default` Submodule
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
    <td>account_ids</td>
    <td>A list of account IDs for which to support cross-account sending of VPC Flow Logs</td>
    <td>[]</td>
    <td>True</td>
  </tr>
  <tr>
    <td>destination_stream_arn</td>
    <td>ARN of the Kinesis Stream to which the Flow Logs should be sent</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>

#### Outputs for `default` Submodule
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>cloudwatch_log_destination_arn</td>
    <td>The ARN of the CloudWatch Logs Destination that will receive Flow Logs</td>
  </tr>
</table>

#### `default` Submodule Example
```hcl
module "flow_logs_default_prod" {
  source                 = "modules/tf_flow_logs/modules/default"
  region                 = "us-east-1",
  prefix                 = "orgname",
  cluster                = "prod",
  account_ids            = ["123456789012"]
  destination_stream_arn = "arn:aws:kinesis:region:account-id:stream/stream-name"
}
```

### `internal` Submodule
The `internal` submodule creates the resources needed to enable VPC Flow Log delivery in the "local"
account. This creates the actual Flow Logs for the specified VPCs, Subnets, and ENIs and uses a
CloudWatch Logs Group to forward to the CloudWatch Logs Destination. If only sending logs cross-account,
these same resources must exist in the _producer_ account, not here.

#### Components for `internal` Submodule
* A CloudWatch Log Group to store the Flow Logs.
* A CloudWatch Logs Subscription Filter that will deliver logs to the specified CloudWatch Logs Destination.
* Enables Flow Logs for resources specified in the `vpcs`, `subnets`, and `enis` variables.
* IAM Role and Policy to allow Flow Logs to be delivered to the CloudWatch Logs Group.

#### Inputs for `internal` Submodule
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
    <td>cloudwatch_log_destination_arn</td>
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

#### Outputs for `internal` Submodule
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>cloudwatch_log_group</td>
    <td>The ARN of the Cloudwatch Log Group to which Flow Log events will be published</td>
  </tr>
</table>

#### `internal` Submodule Example
```hcl
module "flow_logs_internal_prod" {
  source                         = "modules/tf_flow_logs/modules/internal"
  region                         = "us-east-1"
  prefix                         = "orgname"
  cluster                        = "prod"
  cloudwatch_log_destination_arn = "${module.flow_logs_default_prod.cloudwatch_log_destination_arn}"  // Output from above module
  vpcs                           = ["vpc-id-01"]
}
```
