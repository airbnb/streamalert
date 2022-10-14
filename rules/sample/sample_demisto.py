"""
Example for writing a Demisto role
"""
from publishers.sample.sample_demisto import demisto_classification
from streamalert.shared.rule import rule


@rule(logs=['osquery:differential'],
      outputs=['demisto:sample-integration'],
      publishers=[demisto_classification],
      context={
          'demisto': {
              'incident_type': 'My sample type',
              'playbook': 'A Playbook',
              'severity': 'informational'
          },
      })
def sample_demisto(record, _):
    """
    author:           Derek Wang
    description:      An example of how to write a Demisto alert using publishers to classify
    """
    return record.get('hostIdentifier', '') == 'sample_demisto'
