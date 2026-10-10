"""Exact factor-certificate checkers for three historical RSA challenge numbers.

The artifact proves a nontrivial divisor of the fixed modulus by exact integer
division. The verifier makes no probable-prime claim about either factor: that
would require a primality certificate and is not needed to establish a valid
split of the challenge integer.
"""

RSA_1024 = int(
    "135066410865995223349603216278805969938881475605667027524485143851526510604"
    "859533833940287150571909441798207282164471551373680419703964191743046496589"
    "274256239341020864383202110372958725762358509643110564073501508187510676594"
    "629205563685529475213500852879416377328533906109750544334999811150056977236"
    "890927563"
)

RSA_1536 = int(
    "1847699703211741474306835620200164403018549338663410"
    "1714717857749106516967111612498593376843054357445856"
    "1606154457179405222971773252466096064694607124962372"
    "0442022269756756687378427562389508764678440933285157"
    "4965788434150884755282981867264513398633649319080846"
    "7199043187438128336350279547028265329780293491615581"
    "1881049844908319545009848393775227257052578591944993"
    "8700736957556884369338127796130892303925696952532616"
    "20823676490316036551371447913932347169566988069"
)

RSA_2048 = int(
    "251959084756578934940271832400483985714292821262040320277771378360436620207"
    "075955562640185258807844069182906412495150821892985591491761845028084891200"
    "728449926873928072877767359714183472702618963750149718246911650776133798590"
    "957000973304597488084284017974291006424586918171951187461215151726546322822"
    "168699875491824224336372590851418654620435767984233871847744479207399342365"
    "848238242811981638150106748104516603773060562016196762561338441436038339044"
    "149526344321901146575444541784240209246165157233507787077498171257724679629"
    "263863563732899121548314381678998850404453640235273819513786365643912120103"
    "97122822120720357"
)


def _check_factor(artifact: dict, modulus: int) -> tuple[bool, str]:
    if not isinstance(artifact, dict) or set(artifact) != {"factor"}:
        return False, "artifact must be an object containing exactly factor"
    value = artifact["factor"]
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        return False, "factor must be a canonical positive decimal string"
    if value == "0" or (value.startswith("0") and len(value) > 1):
        return False, "factor must be written without a leading zero"
    factor = int(value)
    if not 1 < factor < modulus:
        return False, "factor must be strictly between 1 and the pinned modulus"
    quotient, remainder = divmod(modulus, factor)
    if remainder:
        return False, "factor does not divide the pinned modulus exactly"
    if quotient == 1:
        return False, "factor must leave a nontrivial complementary factor"
    return True, f"verified nontrivial split: {factor.bit_length()}-bit divisor"


def check_rsa1024(artifact: dict) -> tuple[bool, str]:
    return _check_factor(artifact, RSA_1024)


def check_rsa1536(artifact: dict) -> tuple[bool, str]:
    return _check_factor(artifact, RSA_1536)


def check_rsa2048(artifact: dict) -> tuple[bool, str]:
    return _check_factor(artifact, RSA_2048)
