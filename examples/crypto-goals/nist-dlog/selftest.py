import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / 'checkers'))
import nist_dlog as d

for name,c in d.CURVES.items():
    G=(c['gx'],c['gy'])
    assert (c['gy']**2 - (c['gx']**3 - 3*c['gx'] + c['b'])) % c['p'] == 0
    assert d.mul(c['n'],G,c) is None
    q,counter=d.target(name)
    assert 0 <= counter < 1 << 32
    assert (q[1]**2 - (q[0]**3 - 3*q[0] + c['b'])) % c['p'] == 0
    width=(c['n'].bit_length()+3)//4
    k=0x123456789abcdef
    artifact={'k':f'{k:0{width}x}'}
    fixed_target=d.target
    d.target=lambda selected: (d.mul(k,G,c),0) if selected==name else fixed_target(selected)
    assert d.check(name,artifact)
    d.target=fixed_target
    assert not d.check(name,artifact)
    assert not d.check(name,{'k':f'{k+1:0{width}x}'})
    assert not d.check(name,{'k':f'{c["n"]:0{width}x}'})
    assert not d.check(name,{'k':artifact['k'].upper()})
    assert not d.check(name,{'k':artifact['k'],'extra':0})
    print(f'{name}: deterministic point, curve equation, subgroup order, positive and negative controls pass')
