
class LookupTablesError(RuntimeError):
    pass


class LookupTablesInitializationError(LookupTablesError):
    pass


class LookupTablesCommitError(LookupTablesError):
    pass


class LookupTablesConfigurationError(LookupTablesError):
    pass
