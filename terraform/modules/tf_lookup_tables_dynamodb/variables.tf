variable "account_id" {
  description = "AWS Account Id that the DynamoDB tables reside in"
  type        = string
}

variable "region" {
  description = "AWS Region that the DynamoDB tables reside in"
  type        = string
}

variable "prefix" {
  description = "StreamAlert prefix"
  type        = string
}

variable "dynamodb_tables" {
  description = "List of DynamoDB table names to grant LookupTable access to; Cannot be empty!"
  type        = list(string)
}

variable "roles" {
  description = "List of role ids to grant LookupTable access to"
  type        = list(string)
}

// The below is only necessary becuase of:
//  https://github.com/hashicorp/terraform/issues/10857
// Fixed here: https://github.com/hashicorp/terraform/issues/12570#issuecomment-512621787
variable "role_count" {
  description = "Count of role ids to grant LookupTable access to. Note: this is a workaround until terraform v0.12.0 is supported"
}
