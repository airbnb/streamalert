from streamalert.shared.config import load_config


class LookupTablesConfiguration:
    """
    An abstraction around lookup tables configuration. LookupTables can be configured in two places.
    """
    def __init__(self, config=None):
        self._configuration = {}

        if config is None:
            config = load_config()

        self._load_canonical_configurations(config)

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
        return list(self.table_configurations.keys())

    def _load_canonical_configurations(self, config):
        """
        Load the canonical configuration

        The canonical location for LookupTables configuration is in conf/lookup_tables.json
        It expects two keys in this JSON:

            enabled: Boolean. Provide true to enable Lookuptables
            tables:  Dict. Keyed by table names, mapping to dict configurations for each table.

        """
        lookup_tables_configuration = config.get('lookup_tables', False)
        if not (lookup_tables_configuration and lookup_tables_configuration.get('enabled', False)):
            return

        self._configuration = lookup_tables_configuration
