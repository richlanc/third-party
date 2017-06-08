"""
Add dist-packages if python is being called system-wide
"""

import os
import sys

if os.path.dirname(sys.executable) == '/usr/bin':
    sys.path.extend([
        '/usr/lib/python2.7/dist-packages'
    ])
