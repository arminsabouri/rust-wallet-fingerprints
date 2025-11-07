# Python Bindings for rust-wallet-fingerprints

## Building the Package

```shell
# Setup virtual environment/install packages for release
uv sync --all-extras

bash ./generate_linux.sh

# Build the wheel
uv build --wheel

# Force reinstall wallet-fingerprints with <version>
uv pip install ./dist/wallet-fingerprints-*.whl --force-reinstall

# Example:
# uv pip install ./dist/wallet-fingerprints-0.1.0-cp313-cp313-linux_x86_64.whl

# Run all tests
uv run python -m unittest --verbose
```
