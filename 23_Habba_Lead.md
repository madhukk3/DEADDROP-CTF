# Habba Lead — OSINT (300) — SOLVED

> **Description:**
> Last year, a college fest of circuits and code, its name half English and half Kannada, put on a game much like the one you are playing. One person held the keys.
> 
> Translated, their name is a boast: one who has conquered, still young, wearing a mane. Elsewhere, they sign everything with a confession about what was in their bowl.
> 
> They make things, but never by hand. A tireless servant reads their instructions top to bottom, every time. Once, it was handed something it was told to forget.
> 
> **Flag format:** `CTF{...}`

---

## 1. Riddle Deconstruction & Persona Discovery

### A. Fest Identification
* *"A college fest of circuits and code, its name half English and half Kannada"*
  * **Tech** (English) + **Habba** (Kannada for "festival") $\rightarrow$ **Tech Habba** (Acharya Institute of Technology's annual tech fest).
  * *"Last year... put on a game much like the one you are playing. One person held the keys."* $\rightarrow$ The lead organizer of the Tech Habba 2025 CTF.

### B. Name & Handle Decoding
* *"Translated, their name is a boast: one who has conquered, still young, wearing a mane."*
  * **One who has conquered:** **Abhijit** (अभिजीत — victorious / undefeated / one who has conquered).
  * **Still young:** **Kumar** (कुमार — youth / young prince).
  * **Wearing a mane:** **Singh** (सिंह — lion, the beast with a mane).
  * $\rightarrow$ **Abhijit Kumar Singh**
* *"Elsewhere, they sign everything with a confession about what was in their bowl."*
  * Handle: **`IAteNoodles`** (confession of what was eaten from the bowl).
  * Portfolio/bio confirms his role: President & Founding Member of *The Big O Tech Club*, Core Committee Lead for *Tech Habba 2025*.

---

## 2. Locating the "Tireless Servant"

* *"They make things, but never by hand. A tireless servant reads their instructions top to bottom, every time. Once, it was handed something it was told to forget."*
  * **Make things, but never by hand:** Automated build system (`build` / CI/CD).
  * **Tireless servant that reads instructions top to bottom every time:** **GitHub Actions** runner executing a workflow (`.github/workflows/*.yaml`).
  * **Handed something it was told to forget:** A secret / environment variable tagged with a removal comment or intended to be transient.

---

## 3. Extracting the Flag

1. Inspecting Abhijit's profile repository on GitHub: [`IAteNoodles/IAteNoodles`](https://github.com/IAteNoodles/IAteNoodles).
2. Reviewing the commit history reveals commit `74e33352783982d7fe80da86b92975ec45d42766` (*"Create build.yaml"*):
   ```yaml
   name: build
   on: [push]
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Build
           env:
             # debug token, remove before release
             BUILD_TAG: Q1RGezR1dDBtNHQzX3RoM19oNGJiNF9sMzRkM3J9
           run: echo "building"
   ```
3. Notice the comment: `# debug token, remove before release` (*"told to forget"*).
4. Decoding the Base64-encoded `BUILD_TAG`:
   ```bash
   echo "Q1RGezR1dDBtNHQzX3RoM19oNGJiNF9sMzRkM3J9" | base64 -d
   ```
   **Output:**
   ```text
   CTF{4ut0m4t3_th3_h4bb4_l34d3r}
   ```

---

## 4. Flag

`CTF{4ut0m4t3_th3_h4bb4_l34d3r}`
