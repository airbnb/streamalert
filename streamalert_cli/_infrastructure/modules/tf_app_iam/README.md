# StreamAlert App Integration Terraform Module
This Terraform module creates the necessary IAM Permissions to coincide with the Lambda function.

## Components
* IAM Role, Role Policy, and Policy Document to allow for function
  * Invocation of StreamAlert Classifier function
  * Getting the authentication and state parameters from SSM Parameter Store
  * Updating the state parameter in SSM Parameter Store

## Example
```hcl
module "streamalert_app" {
  account_id                   = "123456789012"
  region                       = "us-east-1"
  function_name                = "testprefix_prod_duo_auth_duo_auth_app"
  function_role_id             = "testprefix_prod_duo_auth_duo_auth_app_role_id"
  destination_function_name    = "testprefix_prod_streamalert_classifier
  source                       = "../modules/tf_app_iam"
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
    <td>account_id</td>
    <td>The AWS account ID</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region the Lambda function will run in</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>function_name</td>
    <td>The name of the App Lambda function</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>function_role_id</td>
    <td>The role ID of the App Lambda function, exported from the tf_lambda module</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>destination_function_name</td>
    <td>The name of the Lambda function where App logs should be sent, typically the Classifier function</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>source</td>
    <td>The Terraform source this module should use</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>
