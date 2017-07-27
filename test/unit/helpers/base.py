import io

from contextlib import contextmanager
import mock

# Borrowed from http://bit.ly/2uyWD9X
@contextmanager
def mock_open(filename, contents=None, complain=True):
    """Mock the open() builtin function on a specific filename.

    Let execution pass through to open() on files different than
    `filename`. Return a StringIO with `contents` if the file was
    matched. If the `contents` parameter is not given or if it is None,
    a StringIO instance simulating an empty file is returned.

    If `complain` is True (default), will raise an AssertionError if
    `filename` was not opened in the enclosed block. A NotMocked
    exception will be raised if open() was called with a file that was
    not mocked by mock_open.
    """
    open_files = set()

    def mock_file(*args):
        if args[0] == filename:
            f = io.StringIO(contents.decode('utf-8'))
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
