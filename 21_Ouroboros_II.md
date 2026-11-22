# Ouroboros II — Reverse Engineering (500)
**Flag:** `CTF{r1ng5_4r3_n0t_f13ld5_m4t3!!}`

> (Self-referential VM; the title's "rings not fields" is the whole hint.)

## Idea
The binary is a small VM whose bytecode raises each 16-byte input half `x` to `e=0x15d1f3b28faac2b` in `GF(2)[x]/(P)` and compares against constants. **P is not irreducible**: `P = f60 · f68`, so the ring is `GF(2^60) × GF(2^68)` (a product ring, "not a field"). There `gcd(e, unit-orders) = 1001` and `137`, giving `137137` e-th roots per half. Enumerate all roots in each component, CRT them back, and keep the printable combination.

## How to reproduce
```bash
cd "../Ouroboros-II"
$PY solve.py      # enumerates e-th roots in each ring component, CRTs, prints the printable input -> flag
```

## Solve script

### `solve.py`
```python
# Ouroboros II solver.
# The VM bytecode raises each 16-byte input half x to e=0x15d1f3b28faac2b in GF(2)[x]/(P) and compares with constants.
# P is NOT irreducible: P = f60*f68, so the ring is GF(2^60) x GF(2^68) and gcd(e, unit orders) = 1001 and 137
# -> 137137 e-th roots per half. Enumerate them all via CRT and keep the printable one.
import random
from vm import ins, run
lo=[0x4380ae73,0x20a250a1,0x9d0a4e93,0x31f47583]
P=(1<<128)|sum(w<<(32*i) for i,w in enumerate(lo))
deg=lambda a:a.bit_length()-1
def pmod(a,m):
    while a and deg(a)>=deg(m): a^=m<<(deg(a)-deg(m))
    return a
def pdivmod(a,m):
    q=0
    while a and deg(a)>=deg(m): s=deg(a)-deg(m); q^=1<<s; a^=m<<s
    return q,a
def cmul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a<<=1; b>>=1
    return r
mulm=lambda a,b,m: pmod(cmul(a,b),m)
def pw(a,e,m):
    r=1
    while e:
        if e&1: r=mulm(r,a,m)
        a=mulm(a,a,m); e>>=1
    return r
def egcd(a,b):  # returns (g,s,t) with s*a+t*b=g over GF(2)[x]
    r0,r1,s0,s1,t0,t1=a,b,1,0,0,1
    while r1:
        q,r=pdivmod(r0,r1); r0,r1=r1,r; s0,s1=s1,s0^cmul(q,s1); t0,t1=t1,t0^cmul(q,t1)
    return r0,s0,t0
def factor(n):
    f,p=[],2
    while p*p<=n:
        while n%p==0: f.append(p); n//=p
        p+=1
    return f+([n] if n>1 else [])
F1=pmod(P,1)  # placeholder overwritten below
# irreducible factors of P (found with sympy factor_list over GF(2))
def frombits(ex): return sum(1<<i for i in ex)
f60=frombits([60,56,54,51,49,46,45,44,43,37,35,31,28,25,23,20,16,15,14,12,10,8,6,4,0])
f68=frombits([68,65,62,61,60,59,57,51,49,48,47,46,45,44,43,41,39,34,32,31,30,29,26,23,21,20,18,16,15,13,11,8,7,1,0])
assert cmul(f60,f68)==P
from math import gcd
def roots(t,e,f):
    k=deg(f); n=(1<<k)-1; g=gcd(e,n); m=n//g; assert gcd(g,m)==1
    y=pw(t,pow(e//g,-1,n),f)            # y = x^g
    x0=pw(y,pow(g,-1,m),f); assert pw(x0,e,f)==t
    ps=set(factor(g))
    while True:                          # primitive g-th root of unity
        z=pw(random.getrandbits(k),m,f)
        if z and all(pw(z,g//p,f)!=1 for p in ps): break
    out,c=[],x0
    for _ in range(g): out.append(c); c=mulm(c,z,f)
    return out
_,s,t_=egcd(f60,f68)                    # s*f60 + t*f68 = 1
u1=pmod(cmul(t_,f68),P); u2=pmod(cmul(s,f60),P)
# walk the main program: exponent from square/multiply call pattern, targets from xori/fail compare blocks
halves=[];e=1;cmp={}
for i in range(5076):
    op,a,b,c,imm=ins(i)
    if op==2 and a==0 and b==13: lastld=imm
    if op==3 and a==0 and imm==0x50: last50=lastld
    if op==13: e=e*2 if last50==0x30 else e+1
    if op==16 and a==0 and b==0 and i>40: cmp[lastld]=imm
    if op==15 and i>40 and len(cmp)==4:
        halves.append((e,sum(cmp[0x30+4*k]<<(32*k) for k in range(4)))); e=1; cmp={}
flag=b''
for e,t in halves:
    r1=roots(pmod(t,f60),e,f60); r2=roots(pmod(t,f68),e,f68)
    U=[mulm(a,u1,P) for a in r1]; V=[mulm(b,u2,P) for b in r2]
    good=[]
    for a in U:
        for b in V:
            bs=(a^b).to_bytes(16,'little')
            if all(32<=ch<127 for ch in bs): good.append(bs)
    print(hex(e),len(r1)*len(r2),'roots; printable:',good)
    flag+=good[0]
print(flag, run(flag))

```
