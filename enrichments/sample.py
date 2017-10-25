from stream_alert.alert_processor.output_base import StreamOutputBase
from enrichments import DropAlertException

enrichment = StreamOutputBase.enrichment()

@enrichment
def sample(kwargs):
    """Sample enrichment"""
    
    # Set the header to just the rule name in bold
    kwargs['alert']['header_text'] = "*{}*".format(kwargs['alert']['rule_name'])

    # Set the text before the record to a link to the rule's source code
    kwargs['alert']['pretext'] = "<https://github.com/airbnb/streamalert/tree/master/rules/community/cloudtrail/{}.py|rule source code>".format(kwargs['alert']['rule_name'])

    # If the Slack channel for this alert is set to "prod", but this is not related to the prod account, ignore it.
    # This allows you to use `outputs=["slack:security", "slack:prod"]`, so that all messages will go to the 
    # "security" channel, and only messages related to the prod account will additionally go to the "prod" channel.
    if kwargs['descriptor'] == "prod":
        if 'recipientAccountId' in kwargs['alert']['record'] and \
            kwargs['alert']['record']['recipientAccountId'] != '111111111111':
            raise DropAlertException()
    
    return

