"""Alert on any Duo auth logs marked as a failure due to an Anonymous IP."""
from streamalert.shared.lookup_tables.core import LookupTables
from streamalert.shared.rule import rule


@rule(logs=['duo:authentication'])
def duo_lookup_tables_example(rec):
    """
    description: Alert on Duo auth logs from blacklisted browsers, as defined by a lookup table
    note: This is purely for example purposes in testing, and is not meant to be used as-is
    """
    # The 'global' fixture file at rules/test_fixtures/lookup_tables/dynamo-backed-table.json
    # creates the 'dynamo-backed-table' containing the 'duo_blacklisted_browsers' value
    blacklisted_browsers = LookupTables.get('dynamo-backed-table', 'duo_blacklisted_browsers', [])

    # The test event contains a browser of 'Netscape', which is
    # included in the lookup table blacklist
    return rec['access_device'].get('browser') in set(blacklisted_browsers)
