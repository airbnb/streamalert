"""
Copyright 2017-present, Airbnb Inc.

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
from datetime import timedelta

from streamalert.scheduled_queries.support.clock import Clock


# FIXME (derek.wang)
#  In the future we can evaluate making this into a more customizable system similar to query
#  packs. Users can define their own custom parameters.
class QueryParameterGenerator:
    """This service helps queries generate dynamic parameters."""
    def __init__(self, logger, clock):
        self._logger = logger
        self._clock = clock  # type: Clock

    def generate(self, parameter):
        if parameter == 'utcdatehour_minus7day':
            # https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior
            time = self._clock.now - timedelta(days=7)
            return time.strftime('%Y-%m-%d-%H')

        if parameter == 'utcdatehour_minus1hour':
            time = self._clock.now - timedelta(hours=1)
            return time.strftime('%Y-%m-%d-%H')

        if parameter == 'utctimestamp_minus1hour':
            time = self._clock.now - timedelta(hours=1)
            return str(round(time.timestamp()))

        if parameter == 'utcdatehour_minus2hour':
            time = self._clock.now - timedelta(hours=2)
            return time.strftime('%Y-%m-%d-%H')

        if parameter == 'utcdatehour_minus1day':
            time = self._clock.now - timedelta(days=1)
            return time.strftime('%Y-%m-%d-%H')

        if parameter == 'utcdatehour_minus2day':
            time = self._clock.now - timedelta(days=2)
            return time.strftime('%Y-%m-%d-%H')

        if parameter == 'utcdatehour':
            return self._clock.now.strftime('%Y-%m-%d-%H')

        if parameter == 'utctimestamp':
            return str(round(self._clock.now.timestamp()))

        if parameter == 'utcisotime':
            return str(round(self._clock.now.timestamp()))

        self._logger.error(f'Parameter generator does not know how to handle "{parameter}"')

        return None

    def generate_advanced(self, key, configuration):
        if callable(configuration):
            return configuration(self._clock.now)

        # else, default to whatever generate returns
        return self.generate(key)
