from copy import deepcopy
from publishers.core import AlertPublisher, Register


@Register
def add_record(alert, publication):
    """Publisher that adds the alert.record to the publication."""
    new_publication = deepcopy(publication)

    new_publication['record'] = alert.record

    return new_publication


@Register
def blank(alert, publication):  # pylint: disable=unused-argument
    """Erases all fields on existing publications and returns a blank dict"""
    return {}


@Register
def remove_internal_fields(alert, publication):  # pylint: disable=unused-argument
    """This publisher removes fields from DefaultPublisher that are only useful internally"""

    new_publication = deepcopy(publication)

    new_publication.pop('staged', None)
    new_publication.pop('publishers', None)
    new_publication.pop('outputs', None)

    return new_publication


@Register
class DefaultPublisher(AlertPublisher):
    """The default publisher that is used when no other publishers are provided"""

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
