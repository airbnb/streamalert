import os

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.errors import LookupTablesConfigurationError


class LookupTablesConfiguration(object):
    """
    An abstraction around lookup tables configuration. LookupTables can be configured in two places.
    """
    _DEFAULT_CACHE_REFRESH_MINUTES = 10

    def __init__(self):
        self._configuration = {}

        config = load_config()
        self.load_canonical_configurations(config)
        self.load_legacy_configurations(config)

    def load_canonical_configurations(self, config):
        """
        Load the canonical configuration

        The canonical location for LookupTables configuration is in conf/lookup_tables.json
        It expects two keys in this JSON:

            enabled: Boolean. Provide true to enable Lookuptables
            tables:  Dict. Keyed by table names, mapping to dict configurations for each table.

        """
        lookup_tables_configuration = config['lookup_tables']
        if not (lookup_tables_configuration and lookup_tables_configuration.get('enabled', False)):
            return

        self._configuration = lookup_tables_configuration

    def load_legacy_configurations(self, config):
        """
        Load legacy configuration

        In order to maintain reverse compatibility, we load old lookup_tables configurations from
        global.json. The format of these configurations is outdated, so we merge them into the
        new configuration format.
        """
        lookup_tables_configuration = config['global']['infrastructure'].get('lookup_tables')
        if not (lookup_tables_configuration and lookup_tables_configuration.get('enabled', False)):
            return

        self._configuration['enabled'] = True
        self._configuration['tables'] = self._configuration['tables'] or {}

        for s3_bucket, json_files in lookup_tables_configuration.get('buckets', {}).iteritems():
            for json_file in json_files:
                table_name = os.path.splitext(json_file)[0]
                table_config = {
                    "driver": "s3",
                    "bucket": s3_bucket,
                    "key": json_file,
                    "cache_refresh_minutes": lookup_tables_configuration.get(
                        'cache_refresh_minutes',
                        self._DEFAULT_CACHE_REFRESH_MINUTES
                    ),
                    "compression": "gzip"
                }

                if table_name in self._configuration['tables']:
                    raise LookupTablesConfigurationError(
                        'LookupTables Configuration Error: The \'%s\' table has redundant '
                        'configurations'
                    )

                self._configuration['tables'][table_name] = table_config

    @property
    def is_enabled(self):
        """Returns true when LookupTables is enabled. False otherwise."""
        return self._configuration.get('enabled', False)

    @property
    def table_configurations(self):
        """Returns a dict keyed by table names, mapped to dict table configurations"""
        return self._configuration.get('tables', {})

    @property
    def table_names(self):
        """Returns a list of all of the table names that are configured"""
        return self.table_configurations.keys()
