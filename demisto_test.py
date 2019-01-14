from mock import call, patch
from moto import mock_s3, mock_kms
from nose.tools import assert_false, assert_is_instance, assert_true

from stream_alert.alert_processor.outputs.demisto import DemistoOutput

from tests.unit.stream_alert_alert_processor import (
    CONFIG,
    KMS_ALIAS,
    MOCK_ENV,
    REGION
)
from tests.unit.stream_alert_alert_processor.helpers import (
    get_alert,
    put_mock_creds,
    remove_temp_secrets
)


# client = DemistoClient('MIpC1rrxstLnJqLuz8pxKnJxoIstDFzt', 'https://demisto.ypy.fyi')

@patch.dict('os.environ', MOCK_ENV)
def run_test():
    DESCRIPTOR = 'unit_test_demisto'
    SERVICE = 'demisto'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'url': 'https://demisto.ypy.fyi',
        'token': 'MIpC1rrxstLnJqLuz8pxKnJxoIstDFzt',
    }

    print("START--")
    print(CONFIG)

    # _mock_s3 = mock_s3()
    # _mock_s3.start()
    # _mock_kms = mock_kms()
    # _mock_kms.start()
    # _dispatcher = DemistoOutput(CONFIG)
    # remove_temp_secrets()
    # output_name = _dispatcher.output_cred_name(DESCRIPTOR)
    # put_mock_creds(output_name, CREDS, _dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    _dispatcher = DemistoOutput({

    })

    alert_context = {
        'demisto': {
            'foo': 'bar',
            'baz': 'buzz'
        }
    }

    return _dispatcher.dispatch(get_alert(context=alert_context), OUTPUT)

run_test()

# name = "Derek's test incident #134134"  # The title
# incidenttype = 'Defacement'  # Goes to "unclassified" if not on list
# severity = 3  # 0 is "Unknown" severity, 1 is "Low", 2 is "medium" ... etc. 0.5 is Informational... lol
# owner = 'Derek Wang'  # Shows up verbatim, even if nonexistent
#
# # Instance (e.g. which user corresponding to API key?) is an automatic tag
# # Brand:manual is an automatic tag
# # This is useful for sticking our JSON blob of data
# labels = [
#     {
#         "type": "label",
#         "value": "demisto"
#     },
#     {
#         "type": "from",
#         "value": "machine"
#     },
# ]
#
#
# details = 'Details go here.\n\nCan use newline character to break lines.'
# custom_fields = {
#         "alertsource": "demisto",
#         "custom": "field?",
#         "foo": "bar",
#     }
#
#
# response = client.CreateIncident(
#     name,
#     incidenttype,
#     severity,
#     owner,
#     labels,
#     details,
#     custom_fields,
#     createInvestigation=True,
# )
#
# print(response)
#
# print(response.json())
