# StreamAlert Kinesis Event Terraform Module

* This Terraform module configures a AWS Lambda function to read events from a speecific Kinesis Stream.

## Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>batch_size</td>
    <td>The number of records fetched from Kinesis on a single Lambda invocation</td>
    <td>100</td>
    <td>False</td>
  </tr>  
  <tr>
    <td>kinesis_stream_arn</td>
    <td>The ARN of the Kinesis Stream</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_role_id</td>
    <td>The AWS IAM Role ID attached to the Lambda function</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_production_enabled</td>
    <td>Enable/Disable this event source mapping</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>lambda_function_arn</td>
    <td>The ARN of the Lambda function to read from Kinesis</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>
