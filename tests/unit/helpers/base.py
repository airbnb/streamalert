"""
Copyright 2017-present Airbnb, Inc.

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
import io
from contextlib import contextmanager
from unittest import mock


class NotMocked(Exception):
    """Borrowed from http://bit.ly/2uyWD9X"""

    def __init__(self, filename):
        super().__init__(f"The file {filename} was opened, but not mocked.")

        self.filename = filename


@contextmanager
def mock_open(filename, contents=None, complain=True):  # pylint: disable=unused-argument
    """Mock the open() builtin function on a specific filename.

    Let execution pass through to open() on files different than
    `filename`. Return a BytesIO with `contents` if the file was
    matched. If the `contents` parameter is not given or if it is None,
    a BytesIO instance simulating an empty file is returned.

    If `complain` is True (default), will raise an AssertionError if
    `filename` was not opened in the enclosed block. A NotMocked
    exception will be raised if open() was called with a file that was
    not mocked by mock_open.
    """
    open_files = set()

    def mock_file(*args):
        """Mock file object."""
        if args[0] == filename:
            f = io.BytesIO(contents.decode('utf-8'))
            f.name = filename
        else:
            mocked_file.stop()
            f = open(*args)
            mocked_file.start()
        open_files.add(f.name)
        return f

    mocked_file = mock.patch('__builtin__.open', mock_file)
    mocked_file.start()

    try:
        yield
    except NotMocked as e:
        if e.filename != filename:
            raise

    mocked_file.stop()
