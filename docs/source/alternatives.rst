############
Alternatives
############
It should be noted that the correct choice depends on your use-cases, existing infrastructure, security requirements, available resources, core competencies and more. Details outlined below were considered notable differences and shouldn't constitute a complete, detailed comparison.


**********
ElastAlert
**********

Infrastructure
==============
ElastAlert assumes you have an existing Elasticsearch cluster; it schedules queries against it

StreamAlert directly ingests data from S3 buckets or other sources like Fluentd, Logstash, Kinesis Agent, osquery, PHP, Java, Ruby, etc via Amazon Kinesis Data Streams


Rules/Queries
=============
ElastAlert uses YAML files and Elasticsearch's Query DSL. It supports query types that StreamAlert currently does not, ex: Change, Frequency, Spike, Flatline, New Term, Cardinality

StreamAlert uses JSON files and queries are written in Python; they can utilize any Python libraries or functions


Security
========
In ElastAlert, TLS and authentication is optional (Elasticsearch). This can be enabled via Elastic Shield/X-Pack.

StreamAlert requires TLS for data transport (Kinesis requirement) and authentication is required (AWS Identity and Access Management (IAM))


**********
Etsy's 411
**********

Infrastructure
==============
411 assumes you have an existing Elasticsearch cluster; it schedules queries against it

StreamAlert directly ingests data from S3 buckets or other sources like fluentd, logstash, kinesis-agent, osquery, PHP, Java, Ruby, etc via Amazon Kinesis Data Streams


Rules/Queries
=============
411 uses a custom query language called ESQuery, "Pipelined Lucene shorthand", which is then translated to Elasticsearch's Query DSL

StreamAlert rules/queries are written in Python; they can utilize any Python libraries or functions.


Security
========
411:

* Infrastructure: Apache (w/mod_rewrite, mod_headers), PHP, SQLite, & MySQL. You are responsible for hardening and vulnerability management of these applications and the underlying host / operating system.

* AuthN/AuthZ: The UI is accessed via username/password over TLS. TLS and authentication is optional for Elasticsearch; it can be enabled via Elastic Shield/X-Pack

StreamAlert:

* Infrastructure: Serverless; underlying operating system is hardened and updated by Amazon. Application is Python and runs in a short-lived container/sandbox.
* Requires TLS for data transport (Kinesis requirement)
* AuthN/AuthZ is required (AWS Identity and Access Management (IAM))
