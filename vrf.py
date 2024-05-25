from Crypto.Random import random
from Crypto.Util.number import inverse
from tate_bilinear_pairing import eta, ecc

def get_prime(k):
    """
    Get prime with provided bit length
    """
    pass

def configure(k):
    """
    Configure system by setting public parameters
    k = bit length of prime
    """
    eta.init(k)
    p = ecc._order
    config = {"k": k, "p": p, "g": ecc.gen() }
    print(f"k = {config['k']}")
    print(f"p = {config['p']}")
    print(f"g = {config['g']}")

    return config

def gen(config):
    # pick random s in Zp*
    p = config['p']
    g = config['g']
    s = random.randint(1, p-1)
    print(f"s = {s}")
    gs = ecc.scalar_mult(s, g)
    print(f"gs = {gs}")

    return {"sk": s, "pk": gs }

def prove(sk, x, config):
    """
    x \in Zp*
    """
    p = config['p']
    g = config['g']
    _, xg, yg = g
    egg = eta.pairing(xg, yg, xg, yg)

    a = (x+sk) % p
    ainv = inverse(a, p)

    print(f"e(g,g) = {egg}")
    print(f"x+sk = {a}")
    print(f"1/(x+sk) = {ainv}")
    print(f"(x+sk)*(1/(x+sk)) = {(ainv * a) % p}")

    assert((ainv * a) % p == 1)

    # compute g^(1/(x+sk))
    pi = ecc.scalar_mult(ainv, g)
    print(f"pi = {pi}")

    # sanity check - e(g^(x+sk), g^(1/x+sk)) = e(g,g)
    notpi = ecc.scalar_mult(a, g)
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

def ver(x, y, pi, pk, config):
    """
    x \in Zp*
    y \in Zp*
    """
    g = config['g']

    # compute e(g^x * PK, pi)
    gx = ecc.scalar_mult(x, g)
    gxtimespk = ecc.add(gx, pk)
    print(f"g^x * PK = {gxtimespk}")
    _, x1, y1 = gxtimespk
    _, x2, y2 = pi
    left = eta.pairing(x1, y1, x2, y2)
    print(f"e(g^x * PK, pi) = {left}")

    # compute e(g,g)
    _, xg, yg = g
    right = eta.pairing(xg, yg, xg, yg)
    print(f"e(g,g) = {right}")

    if left != right:
        print("e(g^x * PK, pi) != e(g,g)")
        return False

    # check e(g, pi) = y
    _, x1, y1 = g
    _, x2, y2 = pi
    return eta.pairing(x1, y1, x2, y2) == y

def test():
    x = 10
    k = 151
    config = configure(k)
    keys = gen(config) 
    f, pi = prove(keys['sk'], 10, config)
    f2, _ = prove(keys['sk'], 11, config)

    ver(x, f, pi, keys['pk'], config)
    ver(x, f2, pi, keys['pk'], config)

test()
