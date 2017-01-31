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

from nose.tools import assert_equal

from stream_alert.rule_helpers import in_set, last_hour

def test_in_set():
    # basic example
    test_list = ['this', 'is', 'a9', 'test']
    data = 'test'
    result = in_set(data, test_list)
    assert_equal(result, True)

    # with globbing
    host_patterns = {'myhost*', 'yourhost*', 'ahost*'}
    myhost = 'myhost1232312321'
    yourhost = 'yourhost134931'
    ahost = 'ahost12321-test'

    result = all(in_set(x, host_patterns) for x in (myhost, yourhost, ahost))
    assert_equal(result, True)

def test_last_hour():
    time_now = int(time.time())

    thirty_minutes_ago = time_now - 1800
    assert_equal(last_hour(thirty_minutes_ago), True)

    one_hour_ago = time_now - 3600
    assert_equal(last_hour(one_hour_ago), True)

    two_hours_ago = time_now - 7200
    assert_equal(last_hour(two_hours_ago), False)
