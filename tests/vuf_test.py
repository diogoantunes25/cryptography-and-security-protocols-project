from verfun import *
import pytest
import random

@pytest.mark.parametrize(
    ('k', 'reps'),
    (
        (10, 5),
        (30, 5),
        (79, 5),
        (100, 5),
        (151, 5),
        (160, 5)
    )
)
def test(k, reps):
    prover = VUF(k = k)
    verifier = VUF(pk = prover.get_public_key())

    def test_single():
        a = random.randint(1, 1000)
        b = random.randint(1, 1000)
        while b == a:
            b = random.randint(1, 1000)

        siga = prover.sign(a)
        sigb = prover.sign(b)

        return verifier.ver(a, siga) and \
                verifier.ver(b, sigb) and \
                not verifier.ver(a, sigb) and \
                not verifier.ver(b, siga)

    for _ in range(reps):
        assert test_single()
