import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "EmpireAPIWrapper",
    version = "0.0.1",
    author = "Scott Fraser",
    author_email = "quincy.fraser@gmail.com",
    description = ("A Python wrapper for the Empire API"),
    license = "Apache v2.0",
    keywords = "Powershell Empire",
    url = "https://github.com/radioboyQ/EmpireAPIWrapper",
    install_requires=[
        'Requests',
        'Click',
    ],
    test_suite='tests',
    packages=find_packages(exclude=['tests', 'tests.*']),
    long_description=read('README.md'),
)
