"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from streamalert.shared.importer import import_folders


class QueryPackConfiguration:
    def __init__(self, query=None, params=None, name=None, description=None, tags=None):
        if not name:
            raise RuntimeError('Query Pack missing name')

        if not query:
            raise RuntimeError(f'Query Pack "{name}" missing query template')

        if not tags:
            raise RuntimeError(f'Query Pack "{name}" has no tags?')

        self._query_template = query
        self._query_parameters = params
        self._name = name
        self._description = description
        self._tags = tags or []

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
            raise KeyError(msg) from e

    @property
    def query_template(self):
        return self._query_template

    @property
    def query_parameters(self):
        return self._query_parameters

    @property
    def handler(self):
        """
        @deprecated
        Returns one of the, signally which DBMS handles this query
        """
        return None

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
            raise RuntimeError(f'ERROR: Duplicate query pack name: "{name}"')

        cls.QUERY_PACKS[name] = config

    @classmethod
    def load_packs(cls, directories):
        import_folders(*directories)
