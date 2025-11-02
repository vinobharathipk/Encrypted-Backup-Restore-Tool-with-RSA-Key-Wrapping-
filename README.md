"""
Encrypted Backup & Restore Tool with RSA Key Wrapping

Usage examples:
  - Generate keys:
      python backup_tool.py gen-keys --private private.pem --public public.pem --key-size 4096 --encrypt-passphrase

  - Create a backup (file or directory):
      python backup_tool.py backup --in data_folder --out archive.enc --pub public.pem

  - Restore:
      python backup_tool.py restore --in archive.enc --out restored_data --priv private.pem

Notes:
  - If you pass a directory to backup, it will be tarred (no compression).
  - Private key can be encrypted with a passphrase when generated.
  - Format: magic(8) | version(1) | wrap_len(4) | wrapped_key | iv(12) | tag(16) | ciphertext_len(8) | ciphertext
"""

import argparse
import os
import struct
import tarfile
import io
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from getpass import getpass

MAGIC = b"BKUPFMT1"  # 8 bytes
VERSION = 1

def generate_rsa_keys(private_path: str, public_path: str, key_size: int = 4096, encrypt_priv: bool = False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    # Serialize private key
    if encrypt_priv:
        passphrase = getpass("Enter passphrase to encrypt private key: ").encode()
        encryption_algo = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption_algo = serialization.NoEncryption()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )
    with open(private_path, "wb") as f:
        f.write(priv_pem)

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pub_pem)

    print(f"Generated RSA keys: private -> {private_path}, public -> {public_path}")

def load_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def load_private_key(path: str, passphrase_prompt: bool = True):
    with open(path, "rb") as f:
        data = f.read()
    if b"ENCRYPTED" in data and passphrase_prompt:
        passphrase = getpass("Enter passphrase for private key: ").encode()
    else:
        passphrase = None
    return serialization.load_pem_private_key(data, password=passphrase, backend=default_backend())

def tar_input(in_path: str) -> bytes:
    """If in_path is a file return its bytes; if directory, tar it and return bytes."""
    if os.path.isdir(in_path):
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as tar:
            # add directory contents preserving relative paths
            tar.add(in_path, arcname=os.path.basename(in_path))
        return bio.getvalue()
    else:
        with open(in_path, "rb") as f:
            return f.read()

def write_backup_file(out_path: str, wrapped_key: bytes, iv: bytes, tag: bytes, ciphertext: bytes):
    # container format:
    # MAGIC (8), VERSION(1), wrap_len (4, big-endian), wrapped_key, iv(12), tag(16), ciphertext_len(8), ciphertext
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">B", VERSION))
        f.write(struct.pack(">I", len(wrapped_key)))
        f.write(wrapped_key)
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes for AES-GCM")
        f.write(iv)
        if len(tag) != 16:
            raise ValueError("Tag must be 16 bytes for AES-GCM")
        f.write(tag)
        f.write(struct.pack(">Q", len(ciphertext)))
        f.write(ciphertext)

def read_backup_file(in_path: str):
    with open(in_path, "rb") as f:
        magic = f.read(8)
        if magic != MAGIC:
            raise ValueError("Unrecognized backup file format (magic mismatch)")
        version_b = f.read(1)
        version = struct.unpack(">B", version_b)[0]
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")
        wrap_len = struct.unpack(">I", f.read(4))[0]
        wrapped_key = f.read(wrap_len)
        iv = f.read(12)
        tag = f.read(16)
        ciphertext_len = struct.unpack(">Q", f.read(8))[0]
        ciphertext = f.read(ciphertext_len)
        if len(ciphertext) != ciphertext_len:
            raise ValueError("File truncated or corrupted (ciphertext length mismatch)")
        return wrapped_key, iv, tag, ciphertext

def backup(in_path: str, out_path: str, pubkey_path: str):
    data = tar_input(in_path)
    # Generate AES key (256-bit)
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)  # recommended 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(iv, data, associated_data=None)  # ciphertext includes tag at end; but we'll split
    # cryptography's AESGCM returns ciphertext || tag (tag is last 16 bytes)
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]
    # Wrap AES key with RSA-OAEP (SHA-256)
    pubkey = load_public_key(pubkey_path)
    wrapped_key = pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # store
    write_backup_file(out_path, wrapped_key, iv, tag, ct)
    print(f"Backup created: {out_path} (input size {len(data)} bytes, ciphertext {len(ct)} bytes)")

def restore(in_path: str, out_path: str, privkey_path: str):
    wrapped_key, iv, tag, ct = read_backup_file(in_path)
    privkey = load_private_key(privkey_path)
    aes_key = privkey.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    # cryptography expects ciphertext+tag to decrypt
    full_ct = ct + tag
    plaintext = aesgcm.decrypt(iv, full_ct, associated_data=None)
    # We stored either raw file bytes or tar bytes. We'll try to detect tar by magic 'ustar' somewhere.
    # Simpler: if output path is a directory, write tar contents into it; else write file.
    if out_path.endswith(os.sep) or os.path.isdir(out_path):
        # treat plaintext as tar archive
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as tar:
            tar.extractall(path=out_path if out_path.endswith(os.sep) or os.path.isdir(out_path) else out_path)
        print(f"Restored tar archive into directory: {out_path}")
    else:
        # If plaintext is a tar archive and user provided a file path, extract into folder named <out_path>_restored
        try:
            # check if it's a tar
            bio = io.BytesIO(plaintext)
            if tarfile.is_tarfile(bio):
                target_dir = out_path + "_restored"
                with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as tar:
                    tar.extractall(path=target_dir)
                print(f"Restored tar archive into directory: {target_dir}")
            else:
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                print(f"Restored file written to: {out_path}")
        except Exception as e:
            # fallback: write bytes
            with open(out_path, "wb") as f:
                f.write(plaintext)
            print(f"Restored file written to: {out_path} (note: extraction attempt error: {e})")

def main():
    p = argparse.ArgumentParser(description="Encrypted Backup & Restore Tool (RSA key wrapping + AES-GCM)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-keys", help="Generate RSA key pair")
    g.add_argument("--private", required=True, help="Output private key path (PEM)")
    g.add_argument("--public", required=True, help="Output public key path (PEM)")
    g.add_argument("--key-size", type=int, default=4096, help="RSA key size (bits)")
    g.add_argument("--encrypt-passphrase", action="store_true", help="Encrypt private key with passphrase")

    b = sub.add_parser("backup", help="Create encrypted backup")
    b.add_argument("--in", dest="in_path", required=True, help="Input file or directory")
    b.add_argument("--out", dest="out_path", required=True, help="Output encrypted backup file")
    b.add_argument("--pub", dest="pubkey", required=True, help="Public key PEM to wrap AES key")

    r = sub.add_parser("restore", help="Restore encrypted backup")
    r.add_argument("--in", dest="in_path", required=True, help="Input encrypted backup file")
    r.add_argument("--out", dest="out_path", required=True, help="Output file or directory")
    r.add_argument("--priv", dest="privkey", required=True, help="Private key PEM to unwrap AES key")

    args = p.parse_args()
    if args.cmd == "gen-keys":
        generate_rsa_keys(args.private, args.public, key_size=args.key_size, encrypt_priv=args.encrypt_passphrase)
    elif args.cmd == "backup":
        backup(args.in_path, args.out_path, args.pubkey)
    elif args.cmd == "restore":
        restore(args.in_path, args.out_path, args.privkey)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
