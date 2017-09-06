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
import time

from stream_alert.shared import LOGGER


def time_me(func):
    """Timing decorator for wrapping a function"""

    def timed(*args, **kw):
        """Wrapping function"""
        time_start = time.time()
        result = func(*args, **kw)
        time_end = time.time()

        message = '(module) {} (method) {} (time): {:>.4f}ms'.format(
            func.__module__, func.__name__, (time_end - time_start) * 1000
        )

        LOGGER.debug(message)

        return result

    return timed
