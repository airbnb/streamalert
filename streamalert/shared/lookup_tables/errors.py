class LookupTablesError(RuntimeError):
    """Generic class for errors raised from LookupTables systems"""


class LookupTablesInitializationError(LookupTablesError):
    """Any error raised when a specific table/driver is attempting to initialize"""


class LookupTablesCommitError(LookupTablesError):
    """Any error raised when a LookupTable or driver fails to successfully commit changes"""


class LookupTablesConfigurationError(LookupTablesError):
    """Errors raised that detect a misconfiguration for any LookupTables system"""
