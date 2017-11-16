module "alerts_firehose" {
  source     = "alerts_firehose"
  account_id = "${var.account_id}"
  prefix     = "${var.prefix}"
  region     = "${var.region}"
}
