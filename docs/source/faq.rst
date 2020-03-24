###
FAQ
###
Frequently Asked Questions

**What language is StreamAlert written in?**

* The application and rules are written in Python, the infrastructure is written with Terraform
* Code can be found here: https://github.com/airbnb/streamalert

**What license is StreamAlert released under?**

* https://www.apache.org/licenses/LICENSE-2.0

**How much does StreamAlert cost**

* StreamAlert is open source (free)

**What/How can I send data to StreamAlert?**

* See `Datasources <datasources.html>`_

**What scale does StreamAlert operate at?**

* StreamAlert utilizes Kinesis Streams, which can "continuously capture and store terabytes of data per hour from hundreds of thousands of sources" [1]

**What's the maintenance/operational overhead?**

* Limited; StreamAlert utilizes Terraform, Kinesis Streams and AWS Lambda, which means you don't have to manually provision, manage, patch or harden any servers

**Does StreamAlert support analytics, metrics or time series use-cases?**

* StreamAlert itself does not support analytics, metrics or time series use-cases. StreamAlert can send data to such tools or you can use one of many great open source and commercial offerings in this space, including but not limited to Prometheus, DataDog and NewRelic.

**Is StreamAlert intended for synchronous (blocking) or asynchronous decision making?**

* StreamAlert is intended for asynchronous decision making.


**********
Contact Us
**********
Don't see your question answered here?

Feel free to `open an issue <https://github.com/airbnb/streamalert/issues/new>`_, submit a PR, and/or reach out to us on `Slack <https://streamalert.herokuapp.com/>`_
