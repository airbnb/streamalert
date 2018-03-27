# StreamAlert App Integration Terraform Module
This Terraform module creates the necessary IAM Permissions to coincide with the Lambda function. Additionally, this module creates the SSM config parameter for the function.

## Components
* IAM Role, Role Policy, and Policy Document to allow for function
  * Invocation of StreamAlert Rule Processor
  * Getting the config, auth, and state parameters from SSM Parameter Store
  * Updating the state parameter in SSM Parameter Store
* SSM Parameter Store config value

## Example
```
module "stream_alert_app" {
  account_id                   = "123456789012"
  app_config_parameter         = "{\"cluster\": \"prod\", \"prefix\": \"testprefix\", \"interval\": \"rate(1 hour)\", \"type\": \"duo_auth\", \"app_name\": \"duo-auth-app\"}"
  cluster                      = "prod"
  function_prefix              = "testprefix_prod_duo_auth_duo_auth"
  prefix                       = "testprefix"
  region                       = "us-east-1"
  source                       = "../modules/tf_stream_alert_app"
  stream_alert_apps_config     = "${var.stream_alert_apps_config}"
  type                         = "duo_auth"
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
    <td>app_config_parameter</td>
    <td>JSON escaped string of config to be placed in AWS SSM Parameter Store</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>cluster</td>
    <td>The name of the cluster this Lambda function will be running in</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>function_prefix</td>
    <td>The constructed prefix for this function used throughout the Terraform module as a helper</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>prefix</td>
    <td>The resource prefix, normally an organizational name or descriptor</td>
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
    <td>source</td>
    <td>The Terraform source this module should use</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_alert_apps_config</td>
    <td>Map of the apps configuration loaded from conf/lambda.json. Relevant keys are listed below.</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>type</td>
    <td>The type of app integration this Lambda function is for</td>
    <td>None</td>
    <td>True</td>
  </tr>
</table>
