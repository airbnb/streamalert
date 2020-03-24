"""Alert when a DUO bypass code is created that has unlimited use."""
from rules.helpers.base import safe_json_loads
from streamalert.shared.rule import rule


@rule(logs=['duo:administrator'])
def duo_bypass_code_create_unlimited_use(rec):
    """
    author:       @mimeframe
    description:  Alert when a DUO bypass code is created that has unlimited use.
    reference:    https://duo.com/docs/administration-users#generating-a-bypass-code
    """
    return (rec['action'] == 'bypass_create'
            and safe_json_loads(rec['description']).get('remaining_uses') is None)
