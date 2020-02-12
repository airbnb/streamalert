from streamalert.streamquery.shared.import_functions import import_folders

PACKS_DIRECTORY = 'streamalert/streamquery/query_packs/packs/'


class QueryPackConfiguration:
    SUPPORTED_HANDLERS = {
        'athena:csirt'
    }

    INTERVAL_DAILY = 'daily'
    INTERVAL_HOURLY = 'hourly'
    INTERVAL_TWO_HOURS = 'two_hours'

    def __init__(self, query=None, params=None, handler=None, name=None,
                 description=None, tags=None):
        if not name:
            raise RuntimeError('Query Pack missing name')

        if not query:
            raise RuntimeError('Query Pack "{}" missing query template'.format(name))

        if handler not in self.SUPPORTED_HANDLERS:
            raise RuntimeError('Query Pack "{}" specifying unsupported handler'.format(name))

        if not tags:
            raise RuntimeError('Query Pack "{}" has no tags?'.format(name))

        self._query_template = query
        self._query_parameters = params
        self._handler = handler
        self._name = name
        self._description = description
        self._tags = tags if tags else []

        QueryPackRepository.register(self)

    def generate_query(self, **kwargs):
        """Returns a raw SQL query string"""
        try:
            return self.query_template.format(**kwargs)
        except KeyError as e:
            msg = '''
Failed to generate query for pack: "{name}"
The provided query parameters were:
{kwargs}

Error:
{error}
'''.strip().format(name=self.name, error=e, kwargs=kwargs)
            raise KeyError(msg)


    @property
    def query_template(self):
        return self._query_template

    @property
    def query_parameters(self):
        return self._query_parameters

    @property
    def handler(self):
        """Returns one of the, signally which DBMS handles this query"""
        return self._handler

    @property
    def name(self):
        """Returns a name for this query pack"""
        return self._name

    @property
    def description(self):
        """Returns a short description of what this query pack does"""
        return self._description

    @property
    def tags(self):
        """Returns a list of string tags belonging to this query pack"""
        return self._tags


class QueryPackRepository:
    """A repository of all packs"""
    QUERY_PACKS = {}

    @classmethod
    def get_packs(cls):
        """
        Returns:
             list[QueryPack]
        """
        return cls.QUERY_PACKS.values()

    @classmethod
    def register(cls, config):
        """
        Args:
            config (QueryPackConfiguration)
        """
        name = config.name
        if name in cls.QUERY_PACKS:
            raise RuntimeError('ERROR: Duplicate query pack name: "{}"'.format(name))

        cls.QUERY_PACKS[name] = config

    @classmethod
    def load_packs(cls):
        import_folders(PACKS_DIRECTORY)
