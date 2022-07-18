from importlib.metadata import entry_points, packages_distributions
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='PyNetScope',
    version='0.1.3',
    packages=['PyNetScope', 'PyNetScope.tests'],
    url='https://github.com/Selora/PyNetScope',
    license='BSD-2',
    author='Selora',
    author_email='',
    test_require=['pytest'],
    setup_requires=required,
    entry_points = {
        'console_scripts': ['pynetscope=PyNetScope.command_line:main']
    },
    test_suite="tests",
    description='Python library to healp with external pentest Recon (FQDN,IP,NetRange)'
)
