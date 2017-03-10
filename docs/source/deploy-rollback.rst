Rollback
========

When production AWS Lambda functions are published, they become immutable.  If for some reason a published ``production`` version is throwing errors or contains invalid configurations, we can rollback to the previous version.

.. note:: Rollback is only possible for the main StreamAlert AWS Lambda function, aliased as 'alert'.  The current version must also not be '$LATEST' and must be greater than 1.

To initiate a rollback:

``$ ./stream_alert_cli.py lambda rollback --func alert``