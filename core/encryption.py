"""
Encryption utilities for scan results
AES encryption using Fernet (symmetric encryption)
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Union

class ResultsEncryption:
    """
    Encrypts scan results so they cannot be searched or accessed by others
    Uses AES-256 encryption via Fernet
    """
    
    def __init__(self, master_key: Union[str, bytes] = None):
        """
        Initialize encryption with master key
        If no key provided, uses SECRET_KEY from environment
        """
        if master_key is None:
            master_key = os.environ.get('SECRET_KEY', 'default-encryption-key-change-in-production')
        
        if isinstance(master_key, str):
            master_key = master_key.encode()
        
        # Derive a proper Fernet key from the master key using PBKDF2
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'pulledout_salt_v1',  # Fixed salt for deterministic key
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key))
        self.cipher = Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return base64-encoded ciphertext
        
        Args:
            plaintext: JSON string of scan results
            
        Returns:
            Base64-encoded encrypted string
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        encrypted = self.cipher.encrypt(plaintext)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext and return plaintext
        
        Args:
            ciphertext: Base64-encoded encrypted string
            
        Returns:
            Decrypted JSON string
        """
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        encrypted_data = base64.urlsafe_b64decode(ciphertext)
        decrypted = self.cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new random Fernet key for encryption"""
        return Fernet.generate_key().decode('utf-8')


# Global encryption instance (uses SECRET_KEY from environment)
_encryptor = None

def get_encryptor() -> ResultsEncryption:
    """Get global encryption instance"""
    global _encryptor
    if _encryptor is None:
        _encryptor = ResultsEncryption()
    return _encryptor

def encrypt_scan_results(json_data: str) -> str:
    """Convenience function to encrypt scan results"""
    return get_encryptor().encrypt(json_data)

def decrypt_scan_results(encrypted_data: str) -> str:
    """Convenience function to decrypt scan results"""
    return get_encryptor().decrypt(encrypted_data)


# Example usage:
if __name__ == "__main__":
    # Test encryption
    test_data = '{"scan_id": "test-123", "findings": []}'
    
    encryptor = ResultsEncryption()
    encrypted = encryptor.encrypt(test_data)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = encryptor.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == test_data, "Encryption/decryption test failed!"
    print("✓ Encryption test passed!")
