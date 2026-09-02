import os
import hashlib
import math

"""
Feature Extractor Module for Network & File Threat Detection.
Extracts static analysis features including file size, entropy, and cryptographic hashes.
"""

def calculate_entropy(filepath):
    """
    Calculates the Shannon Entropy of a file to detect encryption/obfuscation/packing.
    Higher entropy (close to 8.0) indicates encrypted or compressed file content.
    """
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) == 0:
        return 0.0

    entropy = 0.0
    for x in range(256):
        p = data.count(bytes([x])) / len(data)
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 2)


def sha256(filepath):
    """Calculates SHA256 checksum of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def md5(filepath):
    """Calculates MD5 checksum of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def extract_features(filepath):
    """
    Extracts static features from a file path.
    Returns dictionary with file size, extension, entropy, and hash signatures.
    """
    filesize = os.path.getsize(filepath)
    extension = os.path.splitext(filepath)[1].lower()
    entropy = calculate_entropy(filepath)
    md5_hash = md5(filepath)
    sha256_hash = sha256(filepath)

    return {
        "filesize": filesize,
        "size": filesize,  # Alias for consistency with dataset schema
        "extension": extension,
        "entropy": float(entropy),
        "md5": md5_hash,
        "sha256": sha256_hash
    }
