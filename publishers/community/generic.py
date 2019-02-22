from copy import deepcopy
from stream_alert.shared.publisher import Register


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
