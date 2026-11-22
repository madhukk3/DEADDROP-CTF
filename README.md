# Dead-Drop CTF 2026 — Writeups

My writeups for **Dead-Drop CTF 2026**, hosted at **Acharya Institute of Technology, Bengaluru**.

Two flag formats showed up during the event: `AIT{...}` and `CTF{...}`.

Each file is a standalone writeup: the vulnerability in one paragraph, then the
steps to reproduce it. Scripts are inlined where they are short.

## Solved

| Challenge | Category | Flag |
|---|---|---|
| [Sanity Check](04%20-%20Sanity%20Check.md) | Misc | `AIT{HIDDEN_IN_PL4IN_SIGHT}` |
| [Last Voice](Last_Voice_writeup.md) | Stego | `AIT{7HR33_CH4NN3L5_0N3_M3554G3}` |
| [InstaSnoop](03%20-%20InstaSnoop.md) | Network Forensics | `AIT{p4ck3t5_n3v3r_f0rg3t_0xdr0p}` |
| [AetherCorp Courier Manifests](19%20-%20AetherCorp%20Courier%20Manifests.md) | Web / IDOR | `AIT{tr4ck1ng_numb3r_3num3r4t10n_fTw}` |
| [What's the word?](18%20-%20Whats%20the%20word.md) | Forensics / Cracking | `AIT{w0rd_t0_th3_w1s3}` |
| [Onion](29%20-%20Onion.md) | Reversing / Encoding | `AIT{n0_t34rs_l3ft}` |
| [Nexus Release Portal](17%20-%20Nexus%20Release%20Portal.md) | Web / RCE (CVE-2025-55182) | `AIT{r2s_f1ight_rce_pwn3d}` |
| [Brew Trail](brew%20trail.md) | OSINT | `AIT{MANOJ_KUMAR}` |
| [Habba Lead](23_Habba_Lead.md) | OSINT | `CTF{4ut0m4t3_th3_h4bb4_l34d3r}` |
| [Mirror of Lost Souls](Mirror%20of%20Lost%20Souls%20-%20Writeup.md) | Web | `AIT{b3y0nd_th3_v3il_0f_s0uls}` |
| [Relay Echo](Relay%20Echo%20-%20Writeup.md) | Web / SSRF | `AIT{r3l4y_3ch0_us3rinf0_sp00f_9d41}` |
| [Lantern Ledger](Lantern_Ledger_writeup.md) | Web / JWT | `AIT{l4nt3rn_k1d_tr4v3rs4l_nu11_k3y_b3f8}` |
| [Severance Window](Severance_Window_writeup.md) | Web / Stego | `AIT{r3pl4c3d_by_3xp1r3d_jwts_4nd_h3x}` |
| [Ghost Relay](Ghost_Relay_writeup.md) | Reversing | `AIT{d34d_dr0p_b3tw33n_th3_fr4m3s}` |
| [Ouroboros II](21_Ouroboros_II.md) | Reversing / Crypto | `CTF{r1ng5_4r3_n0t_f13ld5_m4t3!!}` |
| [Dead Air](Dead_Air_writeup.md) | Forensics / Crypto / Stego | `AIT{THE_L4ST_S!GN4L_W4S_NEVER_SENT}` |
| [Tallow](Tallow_writeup.md) | Forensics | `CTF{th3_c4ndl3_r3m3mb3rs_th3_sh4p3_0f_th3_0ld_m0uld}` |
| [Please Don't Call](Please_Dont_Call_writeup.md) | Forensics / Stego | `AIT{D14L3D_BUT_N3V3R_C4LL3D}` |
| [Ghost Telemetry](Ghost_Telemetry_writeup.md) | Signals / SSTV | `AIT{r34l_s1gn4l_1n_th3_b4s3}` |
| [No Plaintext on 56k](No_Plaintext_on_56k_writeup.md) | Signals / Forensics | `AIT{56K_SECRET_BEEP}` |
| [Page Left Behind](Page_Left_Behind_writeup.md) | Signals / Forensics | `AIT{d3m0dul4t3d_4n_0ld_ch4t_succ3ssfu11y}` |
| [Undertow](Undertow_writeup.md) | RF / Signals | `CTF{und3r_th3_n01s3_fl00r_ch1rps_s1ng}` |
| [Slate](35_Slate.md) | Hardware / NAND forensics | `CTF{b4d_bl0ck5_k33p_g00d_s3cr3ts_wh1l3_th3_l0g_w4pp3d_4r0und}` |
| [Dual Frequency](Dual_Frequency_writeup.md) | Crypto | `AIT{tw0_m3ss4g3s_0n3_k3y}` |
| [Tiny Key, Big Ego](Tiny_Key_Big_Ego_writeup.md) | Crypto | `AIT{p0lyn0m14ls_c4nt_s4v3_a_t1ny_pr1v4t3_k3y_b48ff6e6acf3}` |
| [Ferrule](Ferrule_writeup.md) | Crypto | `CTF{wi3n3r_f0und_th3_k3y_4nd_th3_r1ng_w4s_4_1i3}` |
| [Toll Bridge](Toll_Bridge_writeup.md) | Crypto | `CTF{0n3_n0nc3_tw0_curv3s_z3r0_s3cr3ts}` |
| [Glitch Probe](glitch.md) | Crypto / Side-channel | `CTF{l4tt1c3s_d0nt_c4r3_4b0ut_y0ur_gl1tch3s}` |
| [Cairn](37_Cairn.md) | Crypto | `CTF{b0rr0w_0n3_st0n3_fr0m_3v3ry_c41rn_4nd_th3_p4th_1s_y0urs}` |
| [Quern](Quern_writeup.md) | Crypto | `CTF{0n3_gl1tch3d_s4lt_r3us3_f0ld5_th3_m0dulus_1n_h4lf}` |
| [Moult](Moult-writeup.md) | Crypto | `CTF{c0nst4nts_c4nc3l_wh3n_th3_gcd_g03s_l1n34r}` |
| [Sundial](Sundial_writeup.md) | Crypto | `CTF{4ll_th3_h0urs_4dd_t0_n00n_wh3n_th3_g0lds_c4nc3l}` |
| [Trivet](Trivet_writeup.md) | Crypto | `CTF{f0ur_sh4d0ws_0n3_3xp0n3nt_n0_r00m_w4s_3n0ugh}` |



[ctf_writeup.md](ctf_writeup.md) is an earlier session summary and overlaps with
the per-challenge files above.
