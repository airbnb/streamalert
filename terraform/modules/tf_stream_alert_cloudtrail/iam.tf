// Role for CloudWatch events
resource "aws_iam_role" "streamalert_cloudwatch_role" {
  name = "${var.prefix}_${var.cluster}_streamalert_cloudwatch_role"
  path = "/streamalert/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

// Policy for CloudWatch to allow write access to Kinesis
resource "aws_iam_role_policy" "streamalert_cloudwatch_policy" {
  name = "${var.prefix}_${var.cluster}_streamalert_cloudwatch"
  role = "${aws_iam_role.streamalert_cloudwatch_role.id}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:PutRecord",
                "kinesis:PutRecords"
            ],
            "Resource": [
                "${var.kinesis_arn}"
            ]
        }
    ]
}
EOF
}
