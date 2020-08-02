from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
build_options = {"include_files": ['./backend']}

import sys
base = 'Win32GUI' if sys.platform=='win32' else None

executables = [
    Executable('main.py', base=base, targetName = 'PasswordManager')
]

setup(name='Password Manager',
      version = '1.0',
      description = 'This is a Simple Utility for Storing your Passwords in a Safe Place. This program doesnt connect to internet in any way.',
      options = {'build_exe': build_options},
      executables = executables)
