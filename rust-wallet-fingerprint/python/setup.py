#!/usr/bin/env python

import os
from setuptools import setup

# TODO: Read version from Cargo.toml
version = "0.1.0"

LONG_DESCRIPTION = """# wallet_fingerprint

## Install the package
```shell
pip install wallet_fingerprint
```

## Usage 
```python
import wallet_fingerprint
"""

setup(
    name="wallet_fingerprint",
    description="The Python language bindings for the wallet_fingerprint",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data=True,
    zip_safe=False,
    packages=["wallet_fingerprint"],
    package_dir={"wallet_fingerprint": "./src/wallet-fingerprint"},
    version=version,
    license="MIT or Apache 2.0",
    has_ext_modules=lambda: True,
)
