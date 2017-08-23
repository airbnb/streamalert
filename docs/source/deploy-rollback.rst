Rollback
========

When production AWS Lambda functions are published, they become immutable.  If for some reason a published ``production`` version is throwing errors or contains invalid configurations, the ``stream_alert_cli`` provides a command to rollback to the previous version.

.. note:: Rollback is only possible for the main StreamAlert AWS Lambda function, aliased as 'alert'.  The current version must also not be '$LATEST' and must be greater than 1.

To initiate a rollback for a specific Lambda function:

``$ ./manage.py lambda rollback --processor rule``
``$ ./manage.py lambda rollback --processor alert``

To initiate a rollback for all functions:

``$ ./manage.py lambda rollback --processor all``
