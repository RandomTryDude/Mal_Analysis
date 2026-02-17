#!/usr/bin/env python3
import hashlib
from datetime import datetime, timedelta

def remove_non_alphanumeric(s):
    """Garde seulement les caractères alphanumériques en majuscules"""
    return ''.join(c.upper() for c in s if c.isalnum())

def validate_key(license_key, date_obj, suffix_length):
    """
    Valide une clé de licence pour une date donnée
    
    Args:
        license_key: La clé à valider (déjà nettoyée)
        date_obj: Date de validation (datetime)
        suffix_length: Nombre de caractères du hash à comparer avec le suffixe
    
    Returns:
        bool: True si la clé est valide
    """
    # Convertir la date au format "20060102" (YYYYMMDD)
    date_str = date_obj.strftime("%Y%m%d")
    
    # Convertir la clé en bytes
    key_bytes = bytearray(license_key.encode('ascii'))
    
    # XOR chaque octet de la clé avec les caractères de la date (en boucle)
    for i in range(len(key_bytes)):
        key_bytes[i] = (key_bytes[i] + ord(date_str[i % len(date_str)])) & 0xFF
    
    # Calculer MD5
    md5_hash = hashlib.md5(key_bytes).digest()
    
    # Convertir en hex
    hex_hash = md5_hash.hex()
    
    # Comparer les derniers caractères
    if len(license_key) < suffix_length:
        return False
    
    license_suffix = license_key[-suffix_length:].lower()
    hash_suffix = hex_hash[-suffix_length:]
    
    return license_suffix == hash_suffix

def generate_license_key(prefix, date_obj, total_length=32):
    """
    Génère une clé de licence valide
    
    Args:
        prefix: Préfixe de la clé (ex: "1002")
        date_obj: Date pour laquelle générer la clé
        total_length: Longueur totale de la clé (32 par défaut pour v1, 27 pour v2)
    
    Returns:
        str: Clé de licence valide
    """
    # Nettoyer le préfixe
    prefix = remove_non_alphanumeric(prefix)
    
    # Calculer combien de caractères on a besoin pour le suffixe
    suffix_length = total_length - len(prefix)
    
    if suffix_length <= 0:
        raise ValueError(f"Le préfixe est trop long ({len(prefix)} >= {total_length})")
    
    # Convertir la date au format "20060102"
    date_str = date_obj.strftime("%Y%m%d")
    
    # On va générer une clé temporaire pour calculer le hash
    # On remplit avec des 'A' pour l'instant
    temp_key = prefix + 'A' * suffix_length
    temp_bytes = bytearray(temp_key.encode('ascii'))
    
    # XOR avec la date
    for i in range(len(temp_bytes)):
        temp_bytes[i] = (temp_bytes[i] + ord(date_str[i % len(date_str)])) & 0xFF
    
    # Calculer MD5
    md5_hash = hashlib.md5(temp_bytes).digest()
    hex_hash = md5_hash.hex()
    
    # Prendre les derniers caractères du hash
    hash_suffix = hex_hash[-suffix_length:].upper()
    
    # Construire la clé finale
    final_key = prefix + hash_suffix
    
    # Vérifier que la clé est valide
    if not validate_key(final_key, date_obj, suffix_length):
        # Si la validation échoue, c'est qu'on doit ajuster
        # On va essayer de bruteforcer le préfixe pour trouver une correspondance
        for attempt in range(10000):
            test_prefix = prefix + str(attempt).zfill(4)
            if len(test_prefix) + suffix_length > total_length:
                break
            
            remaining = total_length - len(test_prefix)
            temp_key = test_prefix + 'A' * remaining
            temp_bytes = bytearray(temp_key.encode('ascii'))
            
            for i in range(len(temp_bytes)):
                temp_bytes[i] = (temp_bytes[i] + ord(date_str[i % len(date_str)])) & 0xFF
            
            md5_hash = hashlib.md5(temp_bytes).digest()
            hex_hash = md5_hash.hex()
            hash_suffix = hex_hash[-remaining:].upper()
            test_key = test_prefix + hash_suffix
            
            if validate_key(test_key, date_obj, remaining):
                return test_key
    
    return final_key

def generate_keys_for_years(prefix, years_valid=5, key_length=32):
    """
    Génère des clés valides pour plusieurs années
    
    Args:
        prefix: Préfixe de la clé
        years_valid: Nombre d'années de validité
        key_length: Longueur de la clé (32 pour v1, 27 pour v2)
    """
    today = datetime.now()
    
    print(f"{'='*70}")
    print(f"Générateur de clés de licence - Digler")
    print(f"{'='*70}")
    print(f"Préfixe: {prefix}")
    print(f"Date: {today.strftime('%Y-%m-%d')}")
    print(f"Longueur: {key_length} caractères")
    print(f"Validité: {years_valid} ans\n")
    
    keys = []
    
    for year_offset in range(years_valid + 1):
        target_date = today - timedelta(days=365 * year_offset)
        
        try:
            key = generate_license_key(prefix, target_date, key_length)
            keys.append((target_date.year, key))
            
            # Vérifier la clé
            suffix_len = key_length - len(remove_non_alphanumeric(prefix))
            is_valid = validate_key(key, target_date, suffix_len)
            
            status = "✓ VALIDE" if is_valid else "✗ INVALIDE"
            print(f"Année {target_date.year}: {key} [{status}]")
            
        except Exception as e:
            print(f"Année {target_date.year}: Erreur - {e}")
    
    print(f"\n{'='*70}")
    return keys

# Exemples d'utilisation
if __name__ == "__main__":
    # Générer des clés v1 (32 caractères)
    print("\n### CLÉS VERSION 1 (32 caractères) ###\n")
    v1_keys = generate_keys_for_years("1002", years_valid=5, key_length=32)
    
    print("\n\n### CLÉS VERSION 2 (27 caractères) ###\n")
    v2_keys = generate_keys_for_years("1002", years_valid=5, key_length=27)
    
    # Test avec une clé personnalisée
    print("\n\n### TEST PERSONNALISÉ ###\n")
    custom_prefix = input("Entrez un préfixe (ex: '1002'): ").strip() or "1002"
    custom_length = int(input("Longueur de clé (27 ou 32): ").strip() or "32")
    
    custom_keys = generate_keys_for_years(custom_prefix, years_valid=3, key_length=custom_length)
    
    print("\n\n### VÉRIFICATION ###")
    if custom_keys:
        test_key = custom_keys[0][1]
        print(f"\nTest de la clé: {test_key}")
        suffix_len = custom_length - len(remove_non_alphanumeric(custom_prefix))
        
        for years_back in range(6):
            test_date = datetime.now() - timedelta(days=365 * years_back)
            is_valid = validate_key(test_key, test_date, suffix_len)
            status = "✓" if is_valid else "✗"
            print(f"  {status} Année {test_date.year}: {'VALIDE' if is_valid else 'Invalide'}")