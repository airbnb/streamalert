Rollback
========

When production AWS Lambda functions are published, they become immutable.

If a published production version is throwing errors, the CLI includes a command to rollback to the previous version.

To initiate a rollback for a specific Lambda function:

``$ ./manage.py lambda rollback --processor rule``
``$ ./manage.py lambda rollback --processor alert``

To initiate a rollback for all functions:

``$ ./manage.py lambda rollback --processor all``
