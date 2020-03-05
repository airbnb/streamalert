###############
Global Fixtures
###############

Each directory of rules can have its own **fixtures** used for testing either ThreatIntel or
LookupTables.

Fixtures for ThreatIntel should be defined within a ``threat_intel`` directory,
and fixtures for LookupTables should be defined within a ``lookup_tables`` directory. Each of
these must exist within the ``test_fixtures`` directory to be applied properly.

These fixture files are only applied to rules within the scope of the **current** directory.
Fixtures will be applied to any subdirectory below which they are defined, unless overridden by
another fixture file somewhere further down the directory tree.

If you would like fixtures to be applied only **specific** rules, they should be placed in
a ``test_fixtures`` directory beside the rule to which they should be applied.
For example: the ``rules/community/onelogin/test_fixtures`` directory within this repository.
