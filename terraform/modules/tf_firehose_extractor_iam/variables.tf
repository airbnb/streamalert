
variable "role_id" {
  description = "Lambda ARN of the Firehose Extractor"
}

variable "artifact_firehose_arn" {
  type = string
  description = "The ARN of the Firehose for StreamAlert normalized artifacts"
}