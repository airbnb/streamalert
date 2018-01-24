Account
=======

Background
----------

StreamAlert can ingest, analyze and alert on data from a wide variety of environments, applications, and systems.

However, the StreamAlert application itself and its supporting services must be deployed in an AWS account of your choosing, either new or existing. Deployment is also fully automated via Terraform.

If you want to try out StreamAlert in a test environment, you can use an `AWS Free Tier <https://aws.amazon.com/free/>`_ account to get some hands-on experience.

User Account
~~~~~~~~~~~~

To deploy StreamAlert, you need to create an AWS user for administration.

First, create a policy with sufficient permissions to attach to a user:

* Go to: Services => IAM => Policies
* Click: Create policy
* Select: Create your Own Policy
* Name the policy 'streamalert', and paste the JSON below in the Policy Document:

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

* Click: Create Policy

Next, create the IAM user account:

* Go to: Services => IAM => Users
* Click: Add user
* Username: streamalert
* Access type: Programmatic access
* Click: Next: Permissions
* Select: Attach existing policies directly
* Attach the previously created streamalert policy
* Click: 'Next: Review', and then 'Create user'

Copy the Access Key ID and Secret Access Key and create an AWS profile:

.. code-block:: bash

  $ aws configure --profile streamalert
  AWS Access Key ID [None]: ACCESS KEY HERE
  AWS Secret Access Key [None]: SECRET ACCESS KEY HERE
  Default region name [None]: REGION GOES HERE
  Default output format [None]: json

Finally, export the following environment variable to activate the profile:

.. code-block:: bash
  
  $ export AWS_PROFILE=streamalert

Configuration
-------------

account_id
~~~~~~~~~~

Add your AWS Account ID to the StreamAlert config:

.. code-block:: bash

  $ python manage.py configure aws_account_id <account_number>

Find your AWS Account ID by following these `instructions <https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html>`_.

prefix
~~~~~~

Add your company or organization name to the StreamAlert config:

.. code-block:: bash

  $ python manage.py configure prefix <company/org name>
