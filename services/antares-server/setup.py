"""Drop ``*.egg-info`` from the sdist. Project metadata stays in pyproject.toml.

setuptools appends the egg-info directory after ``MANIFEST.in`` is applied, so
``global-exclude *.egg-info`` does not keep ``SOURCES.txt`` out of the archive.
This command removes those paths before the tarball is written.
"""

from setuptools import setup
from setuptools.command.sdist import sdist as _sdist


class sdist(_sdist):
    def make_distribution(self) -> None:
        self.filelist.files = [
            name for name in self.filelist.files if ".egg-info" not in name.replace("\\", "/")
        ]
        super().make_distribution()


setup(cmdclass={"sdist": sdist})
