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

Open ``variables.json`` and set ``prefix`` to your company name.

lambda_source_bucket_name
~~~~~~~~~~~~~~~~~~~~~~~~~

Open ``variables.json`` and prefix your organization name in ``lambda_source_bucket_name``, e.g. 'company_name.streamalert.source'
