output "function_arn" {
  value = "${aws_lambda_function.function.arn}"
}

output "role_arn" {
  value = "${aws_iam_role.role.arn}"
}

output "role_id" {
  value = "${aws_iam_role.role.id}"
}
