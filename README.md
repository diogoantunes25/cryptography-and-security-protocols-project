# Cryptography and Security Protocols - Project

This is an implementation of verifiable random functions as described
[here](https://link.springer.com/chapter/10.1007/978-3-540-30580-4_28).

The package includes implementation of [verifiable random functions](./src/verfun/vrf.py)
(which is the main contribution described in the paper), but also of [verifiable
unpredictable functions](./src/verfun/vuf.py) (section 4.1) and [verifiable random functions
using hashing](./src/verfun/hvrf.py) (section 4.3).

For examples on how to use the classes, see the [tests](./tests) provided.

The implementation uses bilinear maps constructed from Tate pairings (as implemented
in this [package](https://pypi.org/project/tate_bilinear_pairing/0.6/)).

## Setup

The recommend way to use the project is to create a Python virtual environment.

```bash
# Create virtual environment
python3 -m venv .venv

# Activate environment
source .venv/bin/activate

# Install dependencies
python3 -m pip install -r requirements.txt
```

## Running the tests

To run the tests, some extra dependencies are required.

```bash
# Activate environemnt (assuming it already exists)
source .venv/bin/activate

# Install testing dependencies
python3 -m pip install -r requirements-dev.txt

# Run the tests
pytest tests
```
