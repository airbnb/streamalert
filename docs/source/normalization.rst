#############
Normalization
#############

StreamAlert has an unannounced feature Data Normalization. In its current implementation, it extracts recognized field names from classified records, and saves them to a top-level key on the same record.

This is useful for rules, as they can be written to compare data fields against IoCs, such as IP Address, instead of writing one rule for each incoming data type. However, there are couple limitations we have identified as we use Normalization internally for a while.

***********
Limitations
***********

“On Which Table Can I Find X?”
==============================

When we search in Athena, it is very difficult to figure out which table(s) contain any particular data type. For example, ``hostname``. Knowing which tables have these data requires memorization.

This is because all of our data is stored in their native formats. These vendor-specific formats are subject to the definitions and conventions of each vendor that provides the log data. In order to use StreamAlert data, users must memorize the log types and schemas of each vendor (e.g. Carbon Black, CloudWatch, CloudTrail, Osquery etc).

Normalization per Schema
========================

Right now, Normalization is configured on a file separate from the schema itself. In addition, this is configured on a vendor-namespace-specific format. For example, many different normalizers apply to all ``carbonblack:*`` data.

It is hard to tell, at a glance, which normalizers are applied to specific schemas, as they exist in a separate file. Additionally, there could be normalizers applied to all schemas within a vendor that are irrelevant.

**************************
Normalization 2.0 (Reboot)
**************************

In Normalization 2.0, we introduce a new lambda function ``Artifact Extractor`` by leveraging `Amazon Kinesis Data Firehose Data Transformation <https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html>`_ feature to extract interesting artifacts from records processed by classifiers. The artifacts will be stored in the same S3 bucket where StreamAlert `Historical Search <historical-search.html>`_ feature uses and the Artifacts will be available for searching via Athena as well.


Artifacts Inventory
===================

An artifact is any field or subset of data within a record that bears meaning beyond the record itself, and is of interest in computer security. For example, a “carbonblack_version” would not be an artifact, as it is meaningless outside of the context of Carbon Black data. However, an ``ip_address`` would be an artifact.

``Artifact Extractor`` Lambda function will build an artifacts inventory based on S3 and Athena services. It enables users to search for all artifacts across whole infrastructure from a single Athena table.

**************
Considerations
**************

The Normalization Reboot will bring us good value in terms of how easy will be to search for artifacts across entire infrastructure in the organization. It will also make it possible to write more efficient scheduled queries to have correlated alerting in place. But, it is worth to mention that there may have some tradeoffs on requiring additional resources, adding additional data delay.

#. Increase in Data Footprint: Each individual original record has the chance to add many artifacts. In practice, this will likely not be a huge issue as each artifact is very small and only contains few fields.

#. Additional Delay: Firehose data transformation will add additional up to 900 seconds of delay on the data available for historical search. 900 seconds is a configurable setting on the Firehose where the artifacts extracted from. Reduce the firehose buffer_interval value if want to reduce delay.

#. High memory usage: Artifact Extractor Lambda function may need at least 3x max(buffer size of firehoses where the artifacts extracted from). Because we are doing lots of data copy in Artifact Extractor lambda function. This may be improved by writing more efficient code in the Artifact Extractor Lambda function..
