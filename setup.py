from setuptools import setup, find_packages

setup(
    name="omnisci3nt",
    version="0.1",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "omnisci3nt = omnisci3nt.omnisci3nt:main",
        ],
    },
    include_package_data=True,
)
