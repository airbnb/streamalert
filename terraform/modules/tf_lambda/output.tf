// Defined only if the Lambda is in a VPC
output "function_vpc_arn" {
  value = "${join(" ", aws_lambda_function.function_vpc.*.arn)}"
}

// Defined only if the Lambda is NOT in a VPC
output "function_no_vpc_arn" {
  value = "${join(" ", aws_lambda_function.function_no_vpc.*.arn)}"
}

output "role_arn" {
  value = "${aws_iam_role.role.0.arn}"
}

output "role_id" {
  value = "${aws_iam_role.role.0.id}"
}
