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

> Note: it might be required to install `openssl`, `libffi` and `gmp`. If you
> use Nix, a flake is provided for convenience.

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

> Note that the tests might take around 5 minutes to run.

## Running a simple program

A toy example can be run to try the VRF. To run the program go to
[./src/verfun](./src/verfun) and run `python3 vrf.py`. An example execution
can be found bellow (the logging was removed to make reading easier).

```bash
[dsa@diogo-antunes:~/work/ist/year4/cryptography-and-security-protocols/project/src/verfun]$ python3 vrf.py
Are you a prover or a verifier? [p/v] p
Insert security parameter: 10
Insert file to store the public parameters to: /tmp/pk.dsa
Public parameters saved to /tmp/pk.dsa
Insert x: 105
Insert file where random element and proof should be stored: /tmp/proof.dsa
Do you want to do it again? [y/n] n
(.venv)
[dsa@diogo-antunes:~/work/ist/year4/cryptography-and-security-protocols/project/src/verfun]$ python3 vrf.py
Are you a prover or a verifier? [p/v] v
Insert file where public parameters were stored: /tmp/pk.dsa
Public parameters loaded from /tmp/pk.dsa
Insert x: 105
Insert file where random element and proof were stored: /tmp/proof.dsa
Proof looks good
Do you want to do it again? [y/n] y
Insert x: 104
Insert file where random element and proof were stored: /tmp/proof.dsa
Invalid proof
Do you want to do it again? [y/n] n
```

## Importing the module

Alternatively, to play around with the module, an interactive REPL can be 
opened and the code imported in the following way:

```bash
[dsa@diogo-antunes:~/work/ist/year4/cryptography-and-security-protocols/project]$ cd src
(.venv)
[dsa@diogo-antunes:~/work/ist/year4/cryptography-and-security-protocols/project/src]$ python3
Python 3.10.14 (main, Mar 19 2024, 21:46:16) [GCC 12.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import verfun
>>> verfun.VRF
<class 'verfun.vrf.VRF'>
>>> vrf = verfun.VRF(k = 10)
k = 10
p = 25411
g = [False, [[525], [1200]], [[819], [1100]]]
gs= [False, [[1488], [513]], [[48], [257]]]
s (sk) = 22297
>>>
```
