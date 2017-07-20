Roadmap
=======

Large deliverables are outlined below. Progress, and smaller features, can be tracked on `Github <https://github.com/airbnb/streamalert/issues>`_

Threat Intelligence
~~~~~~~~~~~~~~~~~~~

Target: Q3 2017

In the near future, StreamAlert will support comparing logs against traditional indicators of compromise (IOCs), which can range from thousands to millions in volume. This will be built in a way that's provider agnostic, allowing you to use ThreatStream, ThreatExchange, or whatever your heart desires.

HTTP Endpoint Support
~~~~~~~~~~~~~~~~~~~~~

Target: Q4 2017

StreamAlert will also support receiving data via an HTTP endpoint. This is for service providers or appliances that only support HTTP endpoints for logging. Example: Akamai

Historical Search
~~~~~~~~~~~~~~~~~

Target: Q3 2017

For historical searching, StreamAlert will use AWS Athena, a serverless, interactive query service that uses Presto to query data in S3. This will allow you to analyze data using SQL for both ad-hoc and scheduled queries.
