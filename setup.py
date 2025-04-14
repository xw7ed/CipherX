from setuptools import setup, find_packages

setup(
    name="CipherX",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pycryptodome",
    ],
    entry_points={
        "console_scripts": [
            "cipherx = src.main:main",
        ],
    },
)
