from Crypto.Random import random
from Crypto.Util.number import inverse
from tate_bilinear_pairing import eta, ecc

class VRFPK:
    """
    VRF public key
    """

    def __init__(self, k: int = None, p: int = None, g = None, gs = None):
        self.k = k
        self.p = p
        self.g = g
        self.gs = gs

class VRF:
    def __init__(self, k: int = None, pk: VRFPK = None):
        if pk is None: self._init_prover(k)
        else: self._init_verifier(pk)

    def _init_prover(self, k: int):
        eta.init(k)

        g = ecc.gen()
        p = ecc._order
        self.sk = random.randint(1, p-1)
        self.pk = VRFPK(k, p, g, ecc.scalar_mult(self.sk, g))

        print(f"k = {self.pk.k}")
        print(f"p = {self.pk.p}")
        print(f"g = {self.pk.g}")
        print(f"gs= {self.pk.gs}")
        print(f"s (sk) = {self.sk}")

    def _init_verifier(self, pk: VRFPK):
        self.pk = pk

    def get_public_key(self):
        return self.pk

    def prove(self, x: int):
        """
        x \in Zp*
        """
        _, xg, yg = self.pk.g
        egg = eta.pairing(xg, yg, xg, yg)

        a = (x+self.sk) % self.pk.p
        ainv = inverse(a, self.pk.p)

        print(f"e(g,g) = {egg}")
        print(f"x+sk = {a}")
        print(f"1/(x+sk) = {ainv}")
        print(f"(x+sk)*(1/(x+sk)) = {(ainv * a) % self.pk.p}")

        assert((ainv * a) % self.pk.p == 1)

        # compute g^(1/(x+sk))
        pi = ecc.scalar_mult(ainv, self.pk.g)
        print(f"pi = {pi}")

        # sanity check - e(g^(x+sk), g^(1/x+sk)) = e(g,g)
        notpi = ecc.scalar_mult(a, self.pk.g)
        print(f"notpi = {notpi}")

        _, xpi, ypi = pi
        _, xnotpi, ynotpi = notpi
        should_be_egg = eta.pairing(xpi, ypi, xnotpi, ynotpi)
        print(f"e(pi, notpi) = {should_be_egg}")

        # compute e(g,g)^(1/(x+sk))
        # by computing e(g, pi)
        _, xpi, ypi = pi
        f = eta.pairing(xg, yg, xpi, ypi)
        print(f"f = {f}")

        return f, pi

    def ver(self, x, y, pi):
        """
        x \in Zp*
        y \in Zp*
        """

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

def test():
    k = 151
    prover = VRF(k = k)
    verifier = VRF(pk = prover.get_public_key())

    f10, pi10 = prover.prove(10)
    f100, pi100 = prover.prove(100)

    # Good case
    if verifier.ver(10, f10, pi10): print("It's legit")
    else: print("Bad stuff")

    # Bad bits
    if verifier.ver(100, f10, pi100): print("It's legit")
    else: print("Bad stuff")

    # Bad proof
    if verifier.ver(100, f100, pi10): print("It's legit")
    else: print("Bad stuff")

    # Bad proof and bad bits
    if verifier.ver(100, f10, pi10): print("It's legit")
    else: print("Bad stuff")

test()
