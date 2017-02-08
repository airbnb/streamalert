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

Find your AWS Account ID by following these instructions: https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html

Open ``variables.json`` and set ``account_id`` to this value.

prefix
~~~~~~

Open ``variables.json`` and set ``prefix`` to your company or organization name.

Administrator
~~~~~~~~~~~~~

To successfully deploy StreamAlert, you need to create an administrative user in the AWS account.

Steps:

* Go to: Services => IAM => Users
* Click: Add user
* Username: streamalert
* Access type: Programmatic access
* Click: Next
* Select: Attach existing policies directly
* Type: AdministratorAccess
* Click: The checkbox next to AdministratorAccess
* Click:  Next (Review), and then Create User

Take the Access Key and Secret Key and add them to your environment variables::

  $ export AWS_ACCESS_KEY_ID="REPLACE_ME"
  $ export AWS_SECRET_ACCESS_KEY="REPLACE_ME"
  $ export AWS_DEFAULT_REGION="us-east-1"
