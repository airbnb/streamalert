Deployment
==========

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.

Initial Build
-------------

Run: ``./stream_alert_cli.py terraform init``

This will create all of the necessary infrastructure

Type 'yes' at each prompt

Staging Deployment
------------------

To publish changes to Staging, run:
``./stream_alert_cli.py lambda deploy --env 'staging' --func '*'``

Production Deployment
---------------------

To publish changes to Production, run:
``./stream_alert_cli.py lambda deploy --env 'production' --func 'alert'``
