"""
Copyright 2017-present Airbnb, Inc.

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
from streamalert.shared.lookup_tables.drivers import PersistenceDriver


# pylint: disable=protected-access
class LookupTablesMagic:
    """Namespace full of magic methods that dig around the public interface of LookupTables.

    These methods are not on the public interface by design to prevent these access patterns from
    being utilized in "normal" Lambda code.
    """
    @staticmethod
    def get_all_table_data(table):
        """
        Return all of the data in the given lookup table as a dict. Only works with S3, and you
        should DEFINITELY AVOID USING THIS.

        Args:
            - table (LookupTable)

        Returns:
            dict
        """
        if table.driver_type != PersistenceDriver.TYPE_S3:
            raise RuntimeError("Cannot use lookup_table helper on non-S3 table.")

        # Make a single dummy call to force the table to initialize
        table.get('dummy', None)

        # Do some black magic tomfoolery
        return table._driver._cache._data

    @staticmethod
    def set_table_value(table, key, new_value):
        """Set a value into a LookupTable and then immediately commit it.

        Args:
            - table (LookupTable)
            - key (str)
            - new_value (str|int|list|dict|mixed)
        """
        table._driver.set(key, new_value)
        table._driver.commit()

    @staticmethod
    def get_all_tables(lookup_tables_core):
        """Returns all lookup tables, keyed by their names

        Args:
        - lookup_tables_core (LookupTablesCore)

        Returns:
             dict[str, LookupTable]
        """
        return lookup_tables_core._tables
