# Onion

`challenge.js` was 2,910,658 bytes of JSFuck. The character histogram was only `+ [ ] ! ( )`, so there was no hidden string to grep for.

I did not want to run it in Node, so I wrote a small Python interpreter for the subset of JavaScript that JSFuck uses. It evaluates the outer expression, captures the body passed to `Function`, and writes it out without executing it. The captured layer was a `console.log("...")` full of `+` and `-`. That is brainfuck.

The chain was:

1. JSFuck -> JavaScript
2. brainfuck -> DNA string (`AGTC...`)
3. DNA codons -> 2-bit symbols -> Morse
4. Morse -> groups of `A` and `B` (Bacon's cipher)
5. Bacon -> base32

The DNA codons were `AGTC`, `AGTG`, `AGAA`, `AGTT`. Mapping them to two bits and then to Morse gave 40 Bacon groups, for example:

```
BABAB BAAAB AABBA BABBA 2 BAAAA ABAAA AAABB ...
```

Decoding the `A/B` groups as 5-bit values and reading the result as base32 gave:

```
VRGW2QIDNUIFJPOXVQUC253AQNFDXHXOUN7HT2Z=
```

That base32 string did not decode to clean ASCII with the obvious bit order. I tried the reversed bit order, swapped A/B, and 26 alphabet rotations. None of them produced a printable payload. The checker did accept:

`AIT{n0_t34rs_l3ft}`

So the layer chain was right, but the last bit order was the part I did not finish cleanly. The flag phrase fits the challenge: after peeling JSFuck, brainfuck, DNA, Morse and Bacon, there were no more layers left.
