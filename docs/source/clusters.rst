Clusters
========

**Background**

StreamAlert will deploy separate infrastructure for each ``cluster`` (environment) you define.

What constitutes a ``cluster`` is up to you.

Example: You could define ``IT``, ``PCI`` and ``Production`` clusters

**Strategy**

Cluster definition is up to you.

Common patterns:

1. Define a single cluster to receive and process data from all of your environments
2. Define a cluster for each of your environments
3. Define a cluster for each organization, which may have one or more environments

Which one you choose is largely dependent on your processes, requirements and how your team organizes itself

Option \(2\) is encouraged because it provides segmentation for ingestion, analysis and storage, on a per-cluster basis, ensuring that folks only have access to the infrastructure and data they need to get their job done.

**Configuration**

Open ``variables.json`` and define the ``clusters`` field.  Each key is the name of a cluster, with its value being which AWS region you want to create it in.

Example::

    "clusters": {
        "corp_laptops": "us-east-1",
        "corp_servers": "us-east-2",
        "pci": "us-east-1",
        "production": "us-west-2"
    },
