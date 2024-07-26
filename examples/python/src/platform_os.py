import os
import platform


def is_windows():
    if os.name == 'nt':
        return True
    if platform.system() == 'Windows':
        return True
    return False
