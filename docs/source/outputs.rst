Outputs
=======

Overview
--------

StreamAlert comes with a flexible alerting framework that can integrate with new or existing case/incident management tools. Rules can send alerts to one or many outputs.

Out of the box, StreamAlert supports:

* **S3**
* **PagerDuty**
* **Slack**

It can also be extended to support any API.  Outputs will be more modular in the near future to better support additional outputs and public contributions.

Adhering to the secure by default principle, all API credentials are encrypted and decrypted using AWS Key Management Service (KMS).

Strategy
--------

A common strategy that has been found to be effective:

* Write your rule, only list Slack as an output
* Identify false positives, refine the rule over a period of time
* "Promote" the rule to production by removing Slack and adding PagerDuty and S3 as outputs

Why:

* Slack alerts are ephemeral, great for new/beta rules
* PagerDuty supports webhooks and can still ping Slack
* S3 will act as a persistent store for production alerts (audit trail, historical context)
