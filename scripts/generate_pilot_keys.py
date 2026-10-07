"""Generate the pilot RSA-2048 keypair into ./keys/ (gitignored; mounted read-only at runtime).

This is LOCAL PILOT CUSTODY, not a KMS/HSM. See docs/PRODUCTION-MAPPING.md.
"""

import os
import stat
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("Error: the 'cryptography' library is required: pip install cryptography")
    sys.exit(1)


def generate_keys(force: bool = False) -> None:
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    keys_dir = os.path.join(root_dir, "keys")
    priv_path = os.path.join(keys_dir, "private.pem")
    pub_path = os.path.join(keys_dir, "public.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path) and not force:
        print("Keys already exist in ./keys. Use --force to regenerate (C6 will refuse ECCs signed by the old key).")
        sys.exit(0)

    print("Generating new RSA 2048-bit keypair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    os.makedirs(keys_dir, exist_ok=True)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    # Containers run as uid 10001; the private key must be readable by that user via the bind mount.
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chmod(pub_path, 0o644)

    # The evidence bind mount must be writable by the container user (uid 10001).
    evidence_dir = os.path.join(root_dir, "evidence_data")
    os.makedirs(evidence_dir, exist_ok=True)
    os.chmod(evidence_dir, 0o777)

    print("Generated:")
    print(f" - {os.path.relpath(priv_path, root_dir)}  (NEVER COMMIT; mounted read-only into croa_plane)")
    print(f" - {os.path.relpath(pub_path, root_dir)}   (mounted read-only into c6_firewall)")
    print(f" - {os.path.relpath(evidence_dir, root_dir)}/  (evidence bind mount, writable by the container user)")


if __name__ == "__main__":
    generate_keys("--force" in sys.argv)
