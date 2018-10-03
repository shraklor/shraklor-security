# setup.py
'''

'''
from setuptools import setup, find_packages

with open('./shraklor/security/_constants.py') as constants:
    exec(constants.read())

NAMESPACE_PACKAGES=['shraklor']

setup(
    name=__APP_NAME__,
    version=__APP_VERSION__,
    description="used to simplify HTTP calls",
    install_requires=['requests'],
    extras_require={'test':['pytest', 'pytest-cov', 'pylint', 'sphinx']}
    packages=find_packages(),
    author='brad.source@gmail.com',
    include_package_data=True,
    namespace_packages=NAMESPACE_PACKAGES,
    url="githib"
)
