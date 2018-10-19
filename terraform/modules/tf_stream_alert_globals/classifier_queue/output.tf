output "sqs_queue_url" {
  value = "${aws_sqs_queue.classifier_queue.id}"
}

output "sqs_queue_arn" {
  value = "${aws_sqs_queue.classifier_queue.arn}"
}
