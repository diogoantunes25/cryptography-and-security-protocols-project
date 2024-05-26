from verfun import *
import pytest
import random

def test_hvrf():
    k = 160
    reps = 5
    prover = VRFHashed(k = k)
    verifier = VRFHashed(pk = prover.get_public_key())

    def test_single():
        a = random.randint(1, 1000)
        b = random.randint(1, 1000)
        while b == a:
            b = random.randint(1, 1000)

        print(f"running test with a = {a} and b = {b}")

        fa, pia = prover.prove(a)
        fb, pib = prover.prove(b)

        return verifier.ver(a, fa, pia) and \
                verifier.ver(b, fb, pib) and \
                not verifier.ver(a, fa, pib) and \
                not verifier.ver(a, fb, pia) and \
                not verifier.ver(a, fb, pib) and \
                not verifier.ver(b, fb, pia) and \
                not verifier.ver(b, fa, pib) and \
                not verifier.ver(b, fa, pia)

    
    for _ in range(reps):
        assert test_single()
