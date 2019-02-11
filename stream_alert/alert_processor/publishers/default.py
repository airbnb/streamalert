from copy import deepcopy
from stream_alert.alert_processor.publishers.core import BaseAlertPublisher, AlertPublisher


@AlertPublisher
class DefaultPublisher(BaseAlertPublisher):
    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    def publish(self, alert, publication):
        return {
            'cluster': alert.cluster or '',
            'context': alert.context or {},
            'created': alert.created.strftime(self.DATETIME_FORMAT),
            'id': alert.alert_id,
            'log_source': alert.log_source or '',
            'log_type': alert.log_type or '',
            'outputs': list(sorted(alert.outputs)),  # List instead of set for JSON-compatibility
            'publishers': alert.publishers or {},
            'record': alert.record,
            'rule_description': alert.rule_description or '',
            'rule_name': alert.rule_name or '',
            'source_entity': alert.source_entity or '',
            'source_service': alert.source_service or '',
            'staged': alert.staged,
        }

    @classmethod
    def name(cls):
        return 'default'


@AlertPublisher
def record(alert, publication):
    """Publisher that adds the record to the publication."""
    new_publication = deepcopy(publication)

    new_publication['record'] = alert.record

    return new_publication


@AlertPublisher
def blank(alert, publication): # pylint: disable=unused-argument
    """This publisher simply erases all fields on existing publications and returns a blank dict"""
    return {}


@AlertPublisher
class RemoveInternalFields(BaseAlertPublisher):
    """This publisher removes fields from DefaultPublisher that are only useful internally"""

    def publish(self, alert, publication):
        new_publication = deepcopy(publication)

        new_publication.pop('staged', None)
        new_publication.pop('publishers', None)
        new_publication.pop('outputs', None)

        return new_publication

    @classmethod
    def name(cls):
        return 'no_internal'


@AlertPublisher
class SamplePublisher1(BaseAlertPublisher):

    def publish(self, alert, publication):
        new_publication = deepcopy(publication)

        new_publication['sample_1'] = 'yay, it worked!'

        return new_publication

    @classmethod
    def name(cls):
        return 'sample_1'


@AlertPublisher
class SamplePublisher2(BaseAlertPublisher):
    def publish(self, alert, publication):
        new_publication = deepcopy(publication)

        new_publication['sample_2'] = 'woo, this also worked!'

        return new_publication

    @classmethod
    def name(cls):
        return 'sample_2'
