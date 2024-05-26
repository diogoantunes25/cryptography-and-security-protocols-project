from Crypto.Random import random
from Crypto.Util.number import inverse
from tate_bilinear_pairing import eta, ecc
import pickle

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

class VRF:
    def __init__(self, k: int = None, pk: VRFPK = None, init_eta: bool = False):
        """
        Initialize verifiable random function.
        The prover should initialize it with some security parameter k.
        The verifier should initialize it with the public key provided by the prover.
        """
        if pk is None: self._init_prover(k)
        else: self._init_verifier(pk, init_eta)

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

    def _init_verifier(self, pk: VRFPK, init_eta: bool):
        self.pk = pk
        if init_eta: eta.init(self.pk.k)

        print(f"k = {self.pk.k}")
        print(f"p = {self.pk.p}")
        print(f"g = {self.pk.g}")
        print(f"gs= {self.pk.gs}")

    def get_public_key(self):
        return self.pk

    def prove(self, x: int):
        """
        Generate random group element and proof of correctness for generation.
        """
        x = x % self.pk.p 
        _, xg, yg = self.pk.g
        egg = eta.pairing(xg, yg, xg, yg)

        a = (x+self.sk) % self.pk.p
        print(f"inverting {a} mod {self.pk.p}")

        # If a is 0, it can't be inverted
        # raising an exception does reveal the secret, but the probability
        # of an adversary picking x s.t. x+self.sk = 0 mod p is the same as
        # the probability of finding the secret key
        if a == 0:
            raise Exception("can't compute the proof")

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

    def ver(self, x, y, pi):
        """
        Verify that the random group elemenent y was generated from x using 
        proof pi.
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

def prover():
    k = int(input("Insert security parameter: "))
    vrf = VRF(k = k)
    pk_file = input("Insert file to store the public parameters to: ")

    with open(pk_file, 'wb') as fh:
        pickle.dump(vrf.get_public_key(), fh)

    print(f"Public parameters saved to {pk_file}")

    again = "y"
    while again == "y":
        x = int(input("Insert x: "))
        proof_file = input("Insert file where random element and proof should be stored: ")
        with open(proof_file, 'wb') as fh:
            obj = vrf.prove(x)
            pickle.dump(obj, fh)

        again = ""
        while again not in ["y", "n"]:
            again = input("Do you want to do it again? [y/n] ")

def verifier():
    pk_file = input("Insert file where public parameters were stored: ")
    with open(pk_file, 'rb') as fh:
        pk = pickle.load(fh)

    vrf = VRF(pk = pk, init_eta = True)

    print(f"Public parameters loaded from {pk_file}")

    again = "y"
    while again == "y":
        x = int(input("Insert x: "))
        proof_file = input("Insert file where random element and proof were stored: ")
        with open(proof_file, 'rb') as fh:
            f, pi = pickle.load(fh)
            print(f"f = {f}")
            print(f"pi = {pi}")

        print(f"ver({x}, {f}, {pi}) = {vrf.ver(x, f, pi)}")
        if vrf.ver(x, f, pi):
            print("Proof looks good")
        else:
            print("Invalid proof")

        again = ""
        while again not in ["y", "n"]:
            again = input("Do you want to do it again? [y/n] ")

def main():
    user_type = ""
    while user_type not in ["p", "v"]:
        user_type = input("Are you a prover or a verifier? [p/v] ") 

    if user_type == "p": prover()
    else: verifier()

if __name__ == "__main__":
    main()
