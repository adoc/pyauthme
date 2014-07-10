import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = []
test_requires = []

setup(name='authme',
      version='0.1',
      description=('Collection of Authentication and Authorization '
                   'classes/functions (including SQLAlchemy extentions)'),
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python"
        ],
      author='Nicholas Long',
      author_email='adoc@webmob.net',
      url='https://github.com/adoc/',
      keywords='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      test_suite='authme',
      install_requires=requires,
      test_requires=test_requires
      )
