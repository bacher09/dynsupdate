try:
    from unittest import TestCase, skip, skipIf
except ImportError:
    from unittest2 import TestCase, skip, skipIf


try:
    from unittest import mock
except ImportError:
    import mock


try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO
