FAQ
===

Frequently Asked Questions

**What is StreamAlert?**

* See `Overview <overview.html>`_

**What language is StreamAlert written in?**

* The application and rules are written in Python, the infrastructure is written with Terraform

**What license is StreamAlert released under?**

* https://www.apache.org/licenses/LICENSE-2.0

**How much does StreamAlert cost**

* StreamAlert is open source (free)

**What environments does StreamAlert support?**

* See `Support <support.html>`_

**How can I send data to StreamAlert?**

* See `Datasources <datasources.html>`_

**What can I send to StreamAlert?**

* See `Datasources <datasources.html>`_

**Why support Kinesis Streams & S3?**

* Some logs go directly to S3 (CloudTrail, S3 Server access logs, AWS Config, ...)
* Some SaaS products provide you access/audit logs in an S3 bucket
* Many companies send logs to S3 or Glacier for long-term retention

**Does StreamAlert support analytics, metrics or time series use-cases?**

* No, there are many great opensource and commercial offerings in this space, including but not limited to Prometheus, DataDog and NewRelic.

**What scale does StreamAlert operate at?**

* StreamAlert utilizes Kinesis Streams, which can "continuously capture and store terabytes of data per hour from hundreds of thousands of sources" [1]

**What's the maintenance/operational overhead?**

* Limited; StreamAlert utilizes Terraform, Kinesis Streams and AWS Lambda, which means you don't have to manually provision, manage, patch or harden any servers




