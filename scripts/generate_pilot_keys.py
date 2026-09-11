import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: The 'cryptography' library is required to generate keys.")
    print("Please install it by running: pip install cryptography")
    sys.exit(1)

def generate_keys(force=False):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    priv_path = os.path.join(root_dir, "croa_plane", "private.pem")
    pub_path = os.path.join(root_dir, "c6_firewall", "public.pem")
    
    if os.path.exists(priv_path) and os.path.exists(pub_path) and not force:
        print("Keys already exist. Use --force to regenerate.")
        sys.exit(0)
        
    print("Generating new RSA 2048-bit keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)
    
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
        
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
        
    print(f"Successfully generated keys:")
    print(f" - Private Key: {os.path.relpath(priv_path, root_dir)} (NEVER COMMIT THIS)")
    print(f" - Public Key:  {os.path.relpath(pub_path, root_dir)}")

if __name__ == "__main__":
    force = "--force" in sys.argv
    generate_keys(force)
