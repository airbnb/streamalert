// SSM Parameter Store value for the base config. Allow this to overwrite existing values
resource "aws_ssm_parameter" "config" {
  name      = "${var.function_prefix}_app_config"
  type      = "SecureString"
  value     = "${var.app_config_parameter}"
  overwrite = true
}
