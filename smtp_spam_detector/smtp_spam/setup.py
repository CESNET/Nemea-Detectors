from setuptools import setup, Extension
import os

SRC_PATH = os.path.relpath(os.path.join(os.path.dirname(__file__), "."))

smtp_spam_detector = Extension('smtp-spam-detector', libraries = ['trap', 'unirec'])

setup(name = 'smtp-spam-detector',
       version = '0.0.1',
       description = 'SMTP spam detection.',
       long_description = 'An autonomous detection of SMTP spam using flow traffic',
       author = 'Ladislav Macoun',
       author_email = 'macoulad@fit.cvut.cz',
       maintainer = 'Ladislav Macoun',
       maintainer_email = 'macoulad@fit.cvut.cz',
       url = 'https://github.com/CESNET/Nemea-Detectors',
       license = 'BSD/GPL',
       platforms = ["Linux"],
       classifiers = [
              'Development Status :: 1 - Alpha',
              'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
              'Operating System :: POSIX :: Linux',
              'Programming Language :: C',
              'Programming Language :: Python :: 2',
              'Programming Language :: Python :: 2.7',
              'Programming Language :: Python :: 3',
              'Programming Language :: Python :: 3.4',
              'Programming Language :: Python :: Implementation :: CPython',
              'Topic :: Software Development :: Libraries',
              'Topic :: System :: Networking :: Monitoring'
       ],
       ext_modules = [pytrapmodule],
       package_dir={ "": SRC_PATH, },
       )
