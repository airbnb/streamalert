from copy import copy
from datetime import datetime


class Clock:
    """A service that provides time and time-manipulation methods"""
    def __init__(self):
        self._internal_time = datetime.utcnow()

    @property
    def now(self):
        """Returns current time as a datetime object.

        (!) EXTREMELY IMPORTANT DETAIL: While this returns a modification-safe copy of the time,
            the internal clock will ALWAYS BE THE SAME and corresponds to the Clock's
            "_internal_time" property.

        Returns:
             datetime
        """
        return copy(self._internal_time)

    def time_machine(self, new_time):
        """Changes the Clock's internal time

        Args:
            new_time (datetime)
        """
        self._internal_time = new_time
