#!/usr/bin/env python3
from Crypto.Cipher import AES
import struct

def bytes_from_qwords(qwords):
    result = b''
    for qw in qwords:
        result += struct.pack('<Q', qw)
    return result

def aes_gcm_decrypt(encrypted_hex, key):
    try:
        data = bytes.fromhex(encrypted_hex.strip().replace(" ", ""))
    except ValueError as e:
        print(f"  [!] fromhex error: {e}")
        return None
    if len(data) < 28:
        print(f"  [!] Trop court: {len(data)} octets")
        return None
    nonce      = data[:12]
    tag        = data[-16:]
    ciphertext = data[12:-16]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return (cipher.decrypt_and_verify(ciphertext, tag), True)   # tag validé
    except ValueError:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return (cipher.decrypt(ciphertext), False)                   # tag mismatch

KNOWN_KEYS = {
    "Digler v1.0.0": bytes_from_qwords([
        0xD2D785F280FFD1C9, 0xC5046532575BB92E,
        0x882497BD982E5CAC, 0xD007B846CC6B63DD,
    ]),
    "Digler v1.0.2": bytes_from_qwords([
        0x46C24C5B91BFD3E0, 0x8B834738AF7613B2,
        0x0EADC20964B21CB1E, 0x0C7577F6EE7DFDC63,
    ]),
}

VERSION_FINGERPRINTS = {
    "Digler v1.0.0": ["digler version 1.0.0", "digler v1.0.0", "1.0.0"],
    "Digler v1.0.2": ["digler version 1.0.2", "digler v1.0.2", "v1.02", "1.0.2"],
}

# Forçage de clé par préfixe de nom (optionnel — surcharge l'auto-détection)
NAME_TO_KEY = {
    "v1.0.0": "Digler v1.0.0",
    "v1.0.2": "Digler v1.0.2",
}

STRINGS_TO_TRY = {
    # ── v1.0.2 ──────────────────────────────────────────────────────────────
    "v1.0.2 #1": "6f4a9a3e0ecde48ed233b58e5e099c2562332838554c9d449797de682648d3d798c11f5d592e3e08c9e741",
    "v1.0.2 #2": "afdbdbcfc0db4ee71c2106f943ab0f067e29aef58a3752d7ecbb1e6fa0e96b1642d81edf8f673f7f66d4cb740536046265c4aabfdc367709d1df98daa21f4c0ea3de5f6b4a65291e05a60e61a2be37fa144ebdeb5728e9a2ff07d9798261b857190a3ecdfcb64af89b838025bed224f702d0409e79e3b8aeb504e6b35524364af4af32a3987726a0505a2efd385a2266025c4d02a88c2671d496499fd4542a93869c08fe0b516051a64ead36bba61ff97636972631622a95e45fc71d37064ecc38fbe645042b4f86e88514318457bff5074bdfa4c59399c3d9ab2bd5f1afc20265c38819713a29b54420adf1333d779bf6eab52010d762e02498358252e7334897f34a4cc815a6b59b1fcb3a1df35366438b1dae1fcc2384e4c2ab1022d004bc0cf7428ecf9c08cdea7625107d7c617a366078208b93f40c29051960df924f826053cdb70decbc7427dd5a74388e2bf756cbd40ddd07d634ef652cb826ce91a9e5e04c4c43b0f6619d252fdf01d000e4652235485a4905a4ce6f4f72c2377116d64f9c63873f129d0e805b6b688b7ee2050cfe115aed3b4f87cc5a86f3c66309fd66a321ee32496ef5276ec8d1dc4dcfeddd",
    "v1.0.2 #3": "58909b69f83f8db77590cb74c1b1ab99a31618cf10bd5654a28483a4998bf6c14e36e7990cac3969202b6157f12ac3c1ae64d19ad05c0cf7ba0df4591d5d635598c8774db8b4c2602e2e9ae670721e5316ffffaacd09198775de08287df33d362feba17cd654f1bb01062512e74e8abac47122bb0ff00c1cac6fac3725f27f4e44f5a742864e7bd1988ae01bf2f9663dd25087540cfc4a4b640bfa3b90",
    "v1.0.2 #4": "f5662a15890a93016f0cac966b58f7ab4eabcd1fd13b3a52ea2e311d41",
    "v1.0.2 #5": "d89dd144d7460b9709e9a722331b28a1991368168ee04f7a9cf0e0498d8398ec",
    "v1.0.2 #6": "db54058c933bef2052f926c0603114cebc5e54f240a5beb807ff1fc5d9235ef715c21730378462fa40ca61acdaa74e0c589c01a7bdf5c9642e469aef",
    "v1.0.2 #7": "711fe30b61ac0a060e6ebd57550e7d4bb315be854e217aa2ffb02d02c5b0ac",
    "v1.0.2 #8": "95e4b784cc12e8e68eff8b91dc91da0a5a39c4b6bb74e6f8bedf9afc677eae38ddb331bcc45bf91f",
    "v1.0.2 #9": "abbb19a57ba4b66c7c917063b8d66421",

    # ── v1.0.0 — string complète depuis IDA (RBX=0x364=868 hex chars) ────────
    "v1.0.0 #1": (
        "2fef8bf3693c9d6c83d8d4c700dbdcbce25d6a737fbec26e50581c516ab5e26f"
        "c96d999344a4f6410fdd3cb356748a13961e08eed4dd58c221a3a3f920e13fa7"
        "64f2bf2f23fa9c4efa811cff830ae03a3ac6e29b2d90387d041f77518018dae7"
        "ef71d2a6c25201c0d9fe6ea399b87ebe28570ef5a3d908e60edf1980ac1dc5eb"
        "c24027ac941b45b9dad748065862bfd573aaa6cd8de39e0362834d9f59c33c35"
        "34a59687f768305230e00ce9b85fa3f877cdeed02fe002b05fd0565c1bf36c51"
        "7a073b707169bab2610d4bf21c2c9f8b09ef0d8535cb767b48d99cdbeaf0af19"
        "30c648054bc3eaf38412681072a25ef0b46270efdc5347c3b70f9c6b275e6955"
        "c3c6b8555788bab848d1e01a69b1df9fb6828e01a1470efc0276516f4cc7c6f2"
        "0bd07b3d522fa4f41ed488b625199947de7b411e843a006d54bafef57146776d"
        "e166cff1f0cd33e04aeedc1ba45343d7064bb92c330255c08de4ea4f13d0db7a"
        "528e9ca2203dc860db23c5cdb66f1aa006cbe4cea49dcaa313bbe0ed6b3c25dd"
        "42a47c20743744318c38d4596b9d8dadcc7cc22e255c5f85787284ea193b83e0"
        "f7fc95ef036695b790c9dc2660de95f21fb1"
    ),
    "v1.0.0 #2": "510807b93478f0f0cdceebffef3901c368f0ebb019a42cd76b520fb3957b44c03131f02c21fa21e698a60580f21e4842f6c33db21d8e",
    "v1.0.0 #3": "9537a58b80f19f00327049fdd245961f4ed143ebffa08d3a6543e019ee",
    "v1.0.0 #4": "b80317e0cf8b39cb52534385bc3cb2e0934d7af62418535f61c7da16a66f6ef6",
    "v1.0.0 #5": " 01dfcc1637f95290c9402458ae2c4ef41c6589af5fcf2f8d43bd8c502f954249849f08e8430decee4191a4a8a605290e609f1509548d3583be24be40",
    "v1.0.0 #6":"0ff5f6c4dcb1fdfb2d7dc6d55f02a92f5e4e4229ac96603507e8a3eb42017ccc8ae0dfe7e897d771",
   
}

PRINTABLE_CHARS = set(
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789'
    ' .,;:!?-_/\\()[]{}@#$%^&*+=<>|~`\'":\t\n\r'
)

def readability_score(data):
    if not data:
        return 0.0
    try:
        text = data.decode('utf-8')
        return sum(1 for c in text if c in PRINTABLE_CHARS) / len(text)
    except UnicodeDecodeError:
        return (sum(1 for b in data if 0x20 <= b <= 0x7E) / len(data)) * 0.5

def detect_version(pt):
    try:
        text = pt.decode('utf-8', errors='ignore').lower()
    except Exception:
        return None
    for version, patterns in VERSION_FINGERPRINTS.items():
        for p in patterns:
            if p in text:
                return version
    return None

def get_forced_key(name):
    """Retourne la clé forcée si le nom commence par un préfixe connu."""
    for prefix, key_label in NAME_TO_KEY.items():
        if name.startswith(prefix):
            return key_label
    return None

def try_all_keys(enc_hex, forced_key_label=None):
    results = []

    keys_to_try = (
        {forced_key_label: KNOWN_KEYS[forced_key_label]}
        if forced_key_label and forced_key_label in KNOWN_KEYS
        else KNOWN_KEYS
    )

    for label, key in keys_to_try.items():
        ret = aes_gcm_decrypt(enc_hex, key)
        if ret is None:
            continue
        pt, tag_ok = ret
        version = detect_version(pt)
        score   = readability_score(pt)
        results.append((label, pt, tag_ok, version, score))

    if not results:
        return None, None, None

    # 1. Tag validé → certitude absolue
    for label, pt, tag_ok, version, score in results:
        if tag_ok:
            return label, version, pt

    # 2. Fingerprint de version
    for label, pt, tag_ok, version, score in results:
        if version:
            return label, version, pt

    # 3. Meilleur score lisibilité
    best = max(results, key=lambda x: x[4])
    return best[0], best[3], best[1]

def run():
    SEP  = "-" * 72
    SEP2 = "=" * 72

    print(f"\n{SEP2}")
    print("  DIGLER AES-GCM DECRYPTOR — key auto-detection")
    print(f"{SEP2}\n")
    print("[*] Cles connues :")
    for label, key in KNOWN_KEYS.items():
        print(f"    {label:20s}  {key.hex()}")
    print()

    summary = []

    for name, enc_hex in STRINGS_TO_TRY.items():
        enc_hex = enc_hex.strip().replace(" ", "")
        nb = len(enc_hex) // 2

        print(f"{SEP}")
        print(f"  [{name}]  ({nb} octets chiffres)")
        print(f"{SEP}")

        forced = get_forced_key(name)
        if forced:
            print(f"  [~] Cle forcee par prefixe : {forced}")

        key_label, version, pt = try_all_keys(enc_hex, forced_key_label=forced)

        if pt is None:
            print("  [-] Echec")
            summary.append((name, "—", "—", "ECHEC"))
            continue

        ret = aes_gcm_decrypt(enc_hex, KNOWN_KEYS[key_label])
        tag_ok = ret[1] if ret else False
        tag_str = "TAG OK" if tag_ok else "tag mismatch"

        try:
            text = pt.decode('utf-8', errors='replace')
        except Exception:
            text = pt.hex()

        score = readability_score(pt)
        print(f"  Cle    : {key_label}  [{tag_str}]  score={score:.2f}")
        print(f"  Hex    : {pt.hex()}")
        print(f"  Texte  : '{text}'")

        if version:
            print(f"\n  *** VERSION DETECTEE : {version} ***")
            print(f"  ==> '{text}'\n")

        summary.append((name, key_label or "?", tag_str, text))

    print(f"\n{SEP2}")
    print("  RESUME FINAL")
    print(f"{SEP2}")
    print(f"  {'Nom':<14} {'Cle':<20} {'Tag':<14}  Plaintext")
    print(f"  {'-'*14} {'-'*20} {'-'*14}  {'-'*36}")
    for name, label, tag_str, text in summary:
        short = text[:55].replace('\n', '\\n').replace('\r', '\\r')
        if len(text) > 55:
            short += "..."
        print(f"  {name:<14} {label:<20} {tag_str:<14}  {short}")
    print()

if __name__ == "__main__":
    run()
