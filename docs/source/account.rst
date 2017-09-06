Account
=======

Background
----------

StreamAlert can accept ingest, analyze and alert on data from a wide range of environments and operating systems.

However, the StreamAlert application itself, and its supporting services, must be deployed in an AWS account of your choosing. Deployment is automated via Terraform and can be done against an existing AWS account or a new isolated AWS account you’ve created for this purpose.

Configuration
-------------
As outlined above, choose or create the AWS account you'll use to house the StreamAlert infrastructure.

If you're interested in demo'ing StreamAlert, you can create a hassle free-tier AWS account `here <https://aws.amazon.com/free/>`_.

account_id
~~~~~~~~~~

Find your AWS Account ID by following these `instructions <https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html>`_.

Add your AWS Accound ID to the StreamAlert config:

.. code-block:: bash

  $ python manage.py configure aws_account_id <account_number>

prefix
~~~~~~

Add your company or organization name to the StreamAlert config:

.. code-block:: bash

  $ python manage.py configure prefix <company/org name>

user account
~~~~~~~~~~~~

To deploy StreamAlert, you need to create an AWS user for administration.

First, create the policy to attach to the user:

* Go to: Services => IAM => Policies
* Click: Create policy
* Select: Create your Own Policy
* Name the policy ``streamalert``, and paste the following as the ``Policy Document``:
* Clock: Create Policy

.. code-block:: json

  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "athena:*",
                "cloudtrail:*",
                "cloudwatch:*",
                "ec2:*FlowLogs",
                "events:*",
                "firehose:*",
                "iam:*",
                "kinesis:*",
                "kms:*",
                "lambda:*",
                "logs:*",
                "s3:*",
                "sns:*",
                "sqs:*"
            ],
            "Resource": "*"
        }
    ]
  }

Next, create the user:

* Go to: Services => IAM => Users
* Click: Add user
* Username: ``streamalert``
* Access type: Programmatic access
* Click: ``Next: Permissions``
* Select: Attach existing policies directly
* Attach the previously created ``streamalert`` policy
* Click: ``Next: Review``, and then ``Create user``

Copy the Access Key ID and Secret Access Key and export them to your environment variables:

.. code-block:: bash

  $ export AWS_ACCESS_KEY_ID="REPLACE_ME"
  $ export AWS_SECRET_ACCESS_KEY="REPLACE_ME"
  $ export AWS_DEFAULT_REGION="us-east-1"

.. note:: Remember to save your credentials in a safe place!
