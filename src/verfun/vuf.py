from Crypto.Random import random
from Crypto.Util.number import inverse
from tate_bilinear_pairing import eta, ecc

class VUFPK:
    """
    VUF public parameters
    Includes g^s (what the paper refers to as the public key) and other public
    parameters.
    """

    def __init__(self, k: int = None, p: int = None, g = None, gs = None):
        self.k = k
        self.p = p
        self.g = g
        self.gs = gs

class VUF:
    def __init__(self, k: int = None, pk: VUFPK = None):
        """
        Initialize verifiable unpredictable function.
        The prover should initialize it with some security parameter k.
        The verifier should initialize it with the public key provided by the prover.
        """
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
        Generate group element (i.e. a signature of x).
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
        Verifies that y is a signature of x.
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
