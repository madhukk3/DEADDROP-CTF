# Brew Trail — Writeup

## Step 1: Analyzing the Packet Capture (`chat.pcap`)

Inspecting the packet capture reveals an unencrypted IRC chat session between two users (**ekan** and **angrycat**):

```text
ekan: Have you tried that coffee I told you about?
angrycat: The Indian one? I've seen it around.
ekan: I've heard they're selling specialty coffee internationally now.
ekan: Do you remember who was behind the whole thing?
angrycat: There was someone working with the foundation long before the coffee became a brand.
ekan: Ohh yeah, wait I forgot his name.
angrycat: Send me the location. I'll try to get more info on him.
ekan: Found the street it's on. Sending you the location. Get me his name.
ekan: 12.972298, 77.610697
angrycat: Yupp i'll try to find out!
```

## Step 2: Geolocation & Identifying the Brand

- **Coordinates:** `12.972298, 77.610697`
- **Location:** Commissariat Road, Ashok Nagar, Bengaluru (Sobha Alexander Plaza)

**Specialty Coffee Brand:**

- The coffee shop located on this street is **Araku Coffee** (their flagship specialty coffee cafe).
- Sourced from tribal cooperatives in the Araku Valley (Andhra Pradesh), Araku Coffee became an international specialty coffee brand with its global flagship in Paris, France.

## Step 3: Finding the Person Behind the Whole Thing

- Before becoming an international brand, the Araku initiative began around 2000 as a socio-economic and regenerative agriculture project by the **Naandi Foundation**.
- The person recognized as the mastermind/visionary behind the Araku transformation and CEO of the Naandi Foundation is **Manoj Kumar**.

> **Note:** If the challenge specifically targeted the Chief Agriculture Advisor working with the foundation since 2004, that is **David Hogg**.

## Flag

```text
AIT{MANOJ_KUMAR}
```
