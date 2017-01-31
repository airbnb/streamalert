Account
=======

**Background**

StreamAlert can accept ingest, analyze and alert on data from a wide range of environments and operating systems.

However, the StreamAlert application itself, and its supporting services, must be deployed in an AWS account of your choosing. Deployment is automated via Terraform and can be done against an existing AWS account or a new isolated AWS account you’ve created for this purpose.

**Configuration**

First, create a free-tier AWS account `here <https://aws.amazon.com/free/>`_.

Next, create an administrator user:
  Go to: Services => IAM => Users
  Click: Add user
  Username: streamalert
  Access type: Programmatic access
  Click: Next
  Select: Attach existing policies directly
  Type: AdministratorAccess
  Click: The checkbox next to AdministratorAccess
  Click:  Next (Review), and then Create User

Export the value of the Access Key and Secret Key presented to environment variables:

``$ export AWS_ACCESS_KEY_ID="anaccesskey"``
``$ export AWS_SECRET_ACCESS_KEY="asecretkey"``
``$ export AWS_DEFAULT_REGION="us-east-1"``

Find your AWS Account ID by following these instructions: https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html

Then open ``variables.json`` and set the ``account_id`` field to this value.

Also fill in your organization name under ``prefix`` and ``lambda_source_bucket_name``.