
class KeyParser(object):

    @staticmethod
    def parse(compound_key):
        """
        Takes a compound key and parses out the table and key name from it. For example, will
        take "table_name.key_prefix.key_id" and return:

            {
                table: "table_name",
                key:   "key_prefix.key_id"
            }

        """
