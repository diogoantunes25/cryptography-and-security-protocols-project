from Crypto.Random import random
from Crypto.Util.number import inverse
from Crypto.Hash import SHA224, SHA256, SHA384, SHA512
from tate_bilinear_pairing import eta, ecc
import math

class VRFPK:
    """
    VRF public parameters
    Includes g^s (what the paper refers to as the public key) and other public
    parameters.
    """

    def __init__(self, k: int = None, p: int = None, g = None, gs = None):
        self.k = k
        self.p = p
        self.g = g
        self.gs = gs

class VRFHashed:

    def __init__(self, k: int = None, pk: VRFPK = None):
        """
        Initialize verifiable random function.
        The prover should initialize it with some security parameter k.
        The verifier should initialize it with the public key provided by the prover.
        """
        if pk is None: self._init_prover(k)
        else: self._init_verifier(pk)

    def pick_hash_function(self, p: int):
        """
        Picks the hash function that goes to the largest domain that fits
        in Zp*.
        """
        bits = math.log2(p)
        if bits < 224:
            raise Exception("bit length too short, no good hash function available")

        if bits < 256:
            return SHA224

        if bits < 384:
            return SHA256

        if bits < 512:
            return SHA384

        return SHA512

    def _init_prover(self, k: int):
        eta.init(k)

        g = ecc.gen()
        p = ecc._order
        print(f"log(order) = {math.log2(ecc._order)} (k is {k})")
        self.sk = random.randint(1, p-1)
        self.pk = VRFPK(k, p, g, ecc.scalar_mult(self.sk, g))
        self.h = self.pick_hash_function(p)

        print(f"k = {self.pk.k}")
        print(f"p = {self.pk.p}")
        print(f"g = {self.pk.g}")
        print(f"gs= {self.pk.gs}")
        print(f"s (sk) = {self.sk}")

    def _init_verifier(self, pk: VRFPK):
        self.pk = pk
        self.h = self.pick_hash_function(pk.p)

    def hash(self, m: int):
        hasher = self.h.new()
        # https://docs.python.org/3/library/stdtypes.html#int.to_bytes
        hasher.update(m.to_bytes((m.bit_length() + 7) // 8, byteorder='little'))
        return int.from_bytes(hasher.digest(), byteorder = "little")

    def get_public_key(self):
        return self.pk

    def prove(self, m: int):
        """
        Generate random group element and proof of correctness for generation.
        """
        x = self.hash(m)

        _, xg, yg = self.pk.g
        egg = eta.pairing(xg, yg, xg, yg)

        a = (x+self.sk) % self.pk.p
        # If a is 0, it can't be inverted
        # raising an exception does reveal the secret, but the probability
        # of an adversary picking x s.t. x+self.sk = 0 mod p is the same as
        # the probability of finding self.sk
        if a == 0:
            raise Exception("can't compute the proof")

        print(f"inverting {a} mod {self.pk.p}")
        ainv = inverse(a, self.pk.p)

        print(f"e(g,g) = {egg}")
        print(f"x+sk = {a}")
        print(f"1/(x+sk) = {ainv}")
        print(f"(x+sk)*(1/(x+sk)) = {(ainv * a) % self.pk.p}")

        assert((ainv * a) % self.pk.p == 1)

        # compute g^(1/(x+sk))
        pi = ecc.scalar_mult(ainv, self.pk.g)
        print(f"pi = {pi}")

        # compute e(g,g)^(1/(x+sk))
        # by computing e(g, pi)
        _, xpi, ypi = pi
        f = eta.pairing(xg, yg, xpi, ypi)
        print(f"f = {f}")

        return f, pi

    def ver(self, m, y, pi):
        """
        Verify that the random group elemenent y was generated from x using 
        proof pi.
        """
        x = self.hash(m)

        # compute e(g^x * PK, pi)
        gx = ecc.scalar_mult(x, self.pk.g)
        gxtimespk = ecc.add(gx, self.pk.gs)
        print(f"g^x * PK = {gxtimespk}")
        _, x1, y1 = gxtimespk
        _, x2, y2 = pi
        left = eta.pairing(x1, y1, x2, y2)
        print(f"e(g^x * PK, pi) = {left}")

        # compute e(g,g)
        _, xg, yg = self.pk.g
        right = eta.pairing(xg, yg, xg, yg)
        print(f"e(g,g) = {right}")

        if left != right:
            print("e(g^x * PK, pi) != e(g,g)")
            return False

        # check e(g, pi) = y
        _, x1, y1 = self.pk.g
        _, x2, y2 = pi
        return eta.pairing(x1, y1, x2, y2) == y


