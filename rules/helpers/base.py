'''
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
'''

import time

from fnmatch import fnmatch

def in_set(data, whitelist):
    """Checks if data exists in any elements of a whitelist.

    Args:
        data: element in list
        whitelist: list/set to search in

    Returns:
        True/False
    """
    return any(fnmatch(data, x) for x in whitelist)

def last_hour(unixtime):
    """Check if a given epochtime is within the last hour.

    Args:
        unixtime: epoch time

    Returns:
        True/False
    """
    # sometimes bash histories do not contain the `time` column
    if unixtime:
        return int(time.time()) - int(unixtime) <= 3600
    else:
        return False
