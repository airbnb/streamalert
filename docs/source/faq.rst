FAQ
===

Frequently Asked Questions

**What is StreamAlert?**

* See `Overview <overview.html>`_

**What language is StreamAlert written in?**

* The application and rules are written in Python, the infrastructure is written with Terraform
* Code can be found here: https://github.com/airbnb/streamalert

**What license is StreamAlert released under?**

* https://www.apache.org/licenses/LICENSE-2.0

**How much does StreamAlert cost**

* StreamAlert is open source (free)

**What environments does StreamAlert support?**

* See `Requirements <requirements.html>`_

**How can I send data to StreamAlert?**

* See `Datasources <datasources.html>`_

**What can I send to StreamAlert?**

* See `Datasources <datasources.html>`_

**Why support Kinesis Streams & S3?**

* Some logs go directly to S3 (CloudTrail, S3 Server access logs, AWS Config, ...)
* Some SaaS products provide you access/audit logs in an S3 bucket
* Many companies send logs to S3 or Glacier for long-term retention

**What scale does StreamAlert operate at?**

* StreamAlert utilizes Kinesis Streams, which can "continuously capture and store terabytes of data per hour from hundreds of thousands of sources" [1]

**What's the maintenance/operational overhead?**

* Limited; StreamAlert utilizes Terraform, Kinesis Streams and AWS Lambda, which means you don't have to manually provision, manage, patch or harden any servers

**Does StreamAlert support analytics, metrics or time series use-cases?**

* StreamAlert itself does not support analytics, metrics or time series use-cases. StreamAlert can send data to such tools or you can use one of many great open source and commercial offerings in this space, including but not limited to Prometheus, DataDog and NewRelic.

**Is StreamAlert intended for synchronous (blocking) or asynchronous decision making?**

* StreamAlert is intended for asynchronous decision making.

**What about historical searching and alerting?**

* This is on our `Roadmap <roadmap.html#historical-search>`_ . StreamAlert will utilize AWS Athena, a serverless, interactive query service that uses Presto. This will allow you to analyze your data using SQL for both ad-hoc and scheduled queries.

