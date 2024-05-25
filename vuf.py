from Crypto.Random import random
from Crypto.Util.number import inverse
from tate_bilinear_pairing import eta, ecc

class VUFPK:
    """
    VUF public key
    """

    def __init__(self, k: int = None, p: int = None, g = None, gs = None):
        self.k = k
        self.p = p
        self.g = g
        self.gs = gs

class VUF:
    def __init__(self, k: int = None, pk: VUFPK = None):
        if pk is None: self._init_prover(k)
        else: self._init_verifier(pk)

    def _init_prover(self, k: int):
        eta.init(k)

        g = ecc.gen()
        p = ecc._order
        self.sk = random.randint(1, p-1)
        self.pk = VUFPK(k, p, g, ecc.scalar_mult(self.sk, g))

        print(f"k = {self.pk.k}")
        print(f"p = {self.pk.p}")
        print(f"g = {self.pk.g}")
        print(f"gs= {self.pk.gs}")
        print(f"s (sk) = {self.sk}")

    def _init_verifier(self, pk: VUFPK):
        self.pk = pk

    def get_public_key(self):
        return self.pk

    def sign(self, x: int):
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
        sig = ecc.scalar_mult(ainv, self.pk.g)
        print(f"pi = {sig}")

        return sig

    def ver(self, x, y):
        """
        x \in Zp*
        y \in Zp*
        """

        # compute e(g^x * PK, sig)
        gx = ecc.scalar_mult(x, self.pk.g)
        gxtimespk = ecc.add(gx, self.pk.gs)
        print(f"g^x * PK = {gxtimespk}")
        _, x1, y1 = gxtimespk
        _, x2, y2 = y
        left = eta.pairing(x1, y1, x2, y2)
        print(f"e(g^x * PK, pi) = {left}")

        # compute e(g,g)
        _, xg, yg = self.pk.g
        right = eta.pairing(xg, yg, xg, yg)
        print(f"e(g,g) = {right}")

        return left == right

def test():
    k = 151
    prover = VUF(k = k)
    verifier = VUF(pk = prover.get_public_key())

    sig10 = prover.sign(10)
    sig100 = prover.sign(100)

    # Good case
    if verifier.ver(10, sig10): print("It's legit")
    else: print("Bad stuff")

    # Bad sig
    if verifier.ver(10, sig100): print("It's legit")
    else: print("Bad stuff")

test()
