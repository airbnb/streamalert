Deploying StreamAlert Infrastructure
====================================

Initial Build
-------------

* After configuring (``variables.json``, ``sources.json``, and ``logs.json``), creating your AWS account, setting up your credentials, and installing prerequisites, run the following:

``$ ./stream_alert_cli.py terraform init``

- Init will create all necessary infrastructure, and deploy both AWS Lambda functions.
- Type 'yes' at each prompt

Normal Deploys
--------------

To deploy changes to Staging:
``$ ./stream_alert_cli.py lambda deploy --env 'staging' --func '*'``

To publish these changes to Production:
``$ ./stream_alert_cli.py lambda deploy --env 'production' --func 'alert'``
