"""Pure-Python verifier for deterministic NIST prime-curve DLP targets."""
import hashlib

CURVES = {
    "p256": {
        "p": int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
        "b": int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
        "n": int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        "gx": int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
        "gy": int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
    },
    "p384": {
        "p": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16),
        "b": int("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
        "n": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
        "gx": int("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
        "gy": int("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16),
    },
    "p521": {
        "p": 2**521 - 1,
        "b": int("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16),
        "n": int("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
        "gx": int("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
        "gy": int("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16),
    },
}


def add(P, Q, c):
    if P is None: return Q
    if Q is None: return P
    p = c["p"]
    x1,y1=P; x2,y2=Q
    if x1 == x2 and (y1+y2) % p == 0: return None
    if P == Q: lam = (3*x1*x1 - 3) * pow(2*y1, -1, p) % p
    else: lam = (y2-y1) * pow((x2-x1) % p, -1, p) % p
    x3=(lam*lam-x1-x2)%p
    return x3, (lam*(x1-x3)-y1)%p


def mul(k, P, c):
    out=None
    while k:
        if k&1: out=add(out,P,c)
        P=add(P,P,c); k >>= 1
    return out


def target(name):
    c=CURVES[name]; p=c["p"]; width=(p.bit_length()+7)//8
    seed=f"cairn/nist-prime-curve-dlog/{name}/v1".encode()
    for counter in range(1<<32):
        digest=hashlib.shake_256(seed+counter.to_bytes(4,"big")).digest(width+32)
        x=int.from_bytes(digest,"big")%p
        rhs=(x*x*x-3*x+c["b"])%p
        y=pow(rhs,(p+1)//4,p)
        if y*y%p == rhs:
            if (y&1) != (digest[-1]&1): y=p-y
            return (x,y), counter
    raise RuntimeError("point search exhausted")


def check(name, artifact):
    if not isinstance(artifact,dict) or set(artifact)!={"k"}: return False
    k=artifact["k"]
    c=CURVES[name]
    width=(c["n"].bit_length()+3)//4
    if not isinstance(k,str) or len(k)!=width or any(ch not in "0123456789abcdef" for ch in k): return False
    scalar=int(k,16)
    if not 1 <= scalar < c["n"]: return False
    return mul(scalar,(c["gx"],c["gy"]),c)==target(name)[0]


def check_p256(artifact): return check("p256",artifact)
def check_p384(artifact): return check("p384",artifact)
def check_p521(artifact): return check("p521",artifact)
