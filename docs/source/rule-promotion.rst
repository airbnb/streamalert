##############
Rule Promotion
##############

To complement the Rule Staging feature, StreamAlert includes an optional Rule Promotion Lambda function.
This Lambda function is invoked on a user-defined interval, and can automatically 'promote' rules out
of staging.

Once rules are promoted, they will send alerts to all user-defined outputs. The function
is also capable of sending digest emails to a Simple Notification Service (SNS) topic with statistics
on how many alerts staged rules have generated.


***********************
Enabling Rule Promotion
***********************
Open the ``conf/lambda.json`` file, and find the ``rule_promotion_config`` section. Toggling the
``enabled`` flag to ``true`` will allow for deployment of the Rule Promotion Lambda function.

**Example**:

.. code-block:: json
  :caption: ``conf/lambda.json``

  {
    "rule_promotion_config": {
      "enabled": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "schedule_expression": "rate(10 minutes)",
      "send_digest_schedule_expression": "cron(30 13 * * ? *)",
      "timeout": 120
    }
  }


*********************
Configuration Options
*********************
A few additional configuration options are available to customize the function to your needs.

=====================================  ===========
Key                                    Description
-------------------------------------  -----------
``schedule_expression``                How often the Rule Promotion Lambda function should be
                                       invoked in an attempt to promote currently staged rules.
                                       This should use AWS's
                                       `Rate or Cron Expression syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html>`_.
``send_digest_schedule_expression``    When to invoke the Rule Promotion Lambda function to send
                                       the alert statistics digest. This should use AWS's
                                       `Rate or Cron Expression syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html>`_.
=====================================  ===========

.. note::

  If either of the expressions used above are in the cron syntax, keep in mind the execution time will
  be relative to UTC, not local time.

The initial implementation of the Rule Promotion function has a hard-coded alert threshold, or the
amount of alerts a rule can safely trigger and still be be auto-promoted to send to user-defined
outputs.

The current default is 0, meaning any rule that is staged and triggers any alerts in the
staging period (default of 48 hours hours) will not be auto-promoted. Manual promotion is possible
via the command outlined in the `Rule Staging CLI Commands <rule-staging.html#toggling-staged-status>`_
section.


**********
Deployment
**********
Deploying the Rule Promotion Lambda function is similar to all of StreamAlert's Lambda functions.
The following command will create all of the necessary infrastructure and deploy the Rule Promotion
function code.

.. code-block:: bash

  python manage.py deploy --functions rule_promo

.. note::

  After the above command is run and the function is deployed, users must
  `subscribe to the SNS topic <https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html>`_
  that is created in order to receive the alert statistics digest emails.


***********************
Alert Statistics Digest
***********************
The alert statistics digest that is sent to the SNS topic will contain information on staging times,
as well as the amount of alerts the staged rule has generated to date. If alerts have been triggered,
a link to Athena query results will also be included to assist in triaging them.


Sample Digest Email
===================
*Alert statistics for 2 staged rule(s) [2018-07-25 13:30:25.915131 UTC]*

::

  ◦ rule_001
        - Staged At:                    2018-07-18 20:50:04.036690 UTC
        - Staged Until:                 2018-07-20 20:50:04.036690 UTC
        - Time Past Staging:            4d 16h 40m
        - Alert Count:                  20
        - Alert Info:                   https://console.aws.amazon.com/athena/home#query/history/0e86ea19-9449-4140-caaa-594b0979ed3d

  ◦ rule_002
        - Staged At:                    2018-07-23 22:30:38.823067 UTC
        - Staged Until:                 2018-07-25 22:30:38.823067 UTC
        - Remaining Stage Time:         0d 9h 0m
        - Alert Count:                  2
        - Alert Info:                   https://console.aws.amazon.com/athena/home#query/history/365853eb-ac8f-49b5-9118-c1c6479b2fbd
