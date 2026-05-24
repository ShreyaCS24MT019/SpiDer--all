# key_generator.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import sys

def generate_key_pair(machine_name):
    """Generate RSA key pair for a machine"""
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    private_key_file = f"{machine_name}_private_key.pem"
    public_key_file = f"{machine_name}_public_key.pem"
    
    with open(private_key_file, 'wb') as f:
        f.write(private_pem)
    
    with open(public_key_file, 'wb') as f:
        f.write(public_pem)
    
    print(f"Generated keys for {machine_name}:")
    print(f"Private key saved: {private_key_file}")
    print(f"Public key saved: {public_key_file}")
    print("\n" + "="*50)
    print(f"{machine_name.upper()} PUBLIC KEY (Share this):")
    print("="*50)
    print(public_pem.decode())
    print("="*50)
    
    return private_key_file, public_key_file

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 key_generator.py <machine_name>")
        print("Example: python3 key_generator.py recursor")
        sys.exit(1)
    
    machine_name = sys.argv[1]
    generate_key_pair(machine_name)
