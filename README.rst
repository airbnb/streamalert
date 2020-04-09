StreamAlert - Serverless, Realtime Data Analysis Framework
==========================================================

.. image:: https://github.com/airbnb/streamalert/workflows/Actions%20CI/badge.svg
  :target: https://github.com/airbnb/streamalert/actions?query=workflow%3AActions+CI

.. image:: https://coveralls.io/repos/github/airbnb/streamalert/badge.svg?branch=master
  :target: https://coveralls.io/github/airbnb/streamalert?branch=master

.. image:: docs/images/sa-banner.png
  :align: center
  :alt: StreamAlert

StreamAlert is a serverless, real-time data analysis framework which empowers you to ingest, analyze,
and alert on data from any environment, using data sources and alerting logic you define. Computer
security teams use StreamAlert to scan terabytes of log data every day for incident detection and
response.

Features
--------

* Rules are written in Python; they can utilize any Python libraries or functions
* Ingested logs and generated alerts can be retroactively searched for compliance and research
* Serverless design is cheaper, easier to maintain, and scales to terabytes per day
* Deployment is automated: simple, safe and repeatable for any AWS account
* Secure by design: least-privilege execution, containerized analysis, and encrypted data storage
* Merge similar alerts and automatically promote new rules if they are not too noisy
* Built-in support for dozens of log types and schemas
* Built-in collection of broadly applicable community rules
* Fully open source and customizable: add your own log schemas, rules, and alert outputs

Ready? Let's `get started! <https://streamalert.readthedocs.io/>`_

Resources
-----------

* `Blog Post <https://medium.com/@airbnbeng/e8619e3e5043>`_
* `User Guide <https://streamalert.io/>`_
* `Slack <https://streamalert.herokuapp.com>`_ (unofficial)
