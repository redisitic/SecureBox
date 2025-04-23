import base64
import hashlib
import os
import sys
from pathlib import Path
from typing import Tuple

import boto3
import click
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()
_S3_BUCKET = os.getenv("SECUREBOX_BUCKET")
_KMS_KEY_ID = os.getenv("SECUREBOX_KMS_KEY_ID")
_MASTER_KEY = os.getenv("SECUREBOX_MASTER_KEY")
_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

if not _S3_BUCKET:
    click.echo("[FATAL] SECUREBOX_BUCKET env var not set", err=True)
    sys.exit(1)

session = boto3.Session(region_name=_REGION)
s3 = session.client("s3")
if _KMS_KEY_ID:
    kms = session.client("kms")
else:
    kms = None

def _generate_data_key() -> Tuple[bytes, bytes]:
    """Return (plaintext_key, encrypted_key)."""
    if kms:
        resp = kms.generate_data_key(KeyId=_KMS_KEY_ID, KeySpec="AES_256")
        return resp["Plaintext"], resp["CiphertextBlob"]
    else:
        plaintext_key = os.urandom(32)
        master = bytes.fromhex(_MASTER_KEY)
        encrypted_key = hashlib.sha256(master + plaintext_key).digest()
        return plaintext_key, encrypted_key

def _decrypt_data_key(enc_key: bytes) -> bytes:
    if kms:
        resp = kms.decrypt(CiphertextBlob=enc_key)
        return resp["Plaintext"]
    else:
        raise ValueError("Plaintext key required when not using KMS")

def encrypt_file(in_path: Path) -> Tuple[bytes, dict]:
    """Encrypt file and return ciphertext + metadata dict"""
    plaintext_key, enc_key = _generate_data_key()
    aesgcm = AESGCM(plaintext_key)
    iv = os.urandom(12)
    data = in_path.read_bytes()
    ct = aesgcm.encrypt(iv, data, None)
    meta = {
        "x-amz-meta-sb-iv": base64.b64encode(iv).decode(),
        "x-amz-meta-sb-key": base64.b64encode(enc_key).decode(),
        "x-amz-meta-sb-algo": "AES256GCM",
        "x-amz-meta-sb-ver": "1",
    }
    if not kms:
        meta["x-amz-meta-sb-ptk"] = base64.b64encode(plaintext_key).decode()
    return ct, meta

def decrypt_blob(blob: bytes, meta: dict) -> bytes:
    iv = base64.b64decode(meta["x-amz-meta-sb-iv"])
    enc_key = base64.b64decode(meta["x-amz-meta-sb-key"])
    if kms:
        ptk = _decrypt_data_key(enc_key)
    else:
        ptk = base64.b64decode(meta["x-amz-meta-sb-ptk"])
    aesgcm = AESGCM(ptk)
    return aesgcm.decrypt(iv, blob, None)

def s3_put(file_path: Path, object_key: str):
    ct, meta = encrypt_file(file_path)
    try:
        s3.put_object(
            Bucket=_S3_BUCKET,
            Key=object_key,
            Body=ct,
            Metadata=meta,
        )
        click.echo(f"[OK] Uploaded {file_path} -> s3://{_S3_BUCKET}/{object_key}")
    except ClientError as e:
        click.echo(f"[ERROR] {e}")

def s3_get(object_key: str, dest_path: Path):
    try:
        obj = s3.get_object(Bucket=_S3_BUCKET, Key=object_key)
        blob = obj["Body"].read()
        meta = obj["Metadata"]
        data = decrypt_blob(blob, meta)
        dest_path.write_bytes(data)
        click.echo(f"[OK] Downloaded to {dest_path}")
    except ClientError as e:
        click.echo(f"[ERROR] {e}")

@click.group()
def cli():
    """SecureBox – client‑side encrypted S3 storage"""

@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--key", "object_key", default=None, help="S3 object key")
def put(file: Path, object_key):
    """Encrypt FILE and upload to S3"""
    object_key = object_key or file.name
    s3_put(file, object_key)

@cli.command()
@click.argument("key", metavar="OBJECT_KEY")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path),
              help="Destination file path")
def get(key, out_path):
    """Download OBJECT_KEY from S3 and decrypt"""
    out_path = out_path or Path(key)
    s3_get(key, out_path)

@cli.command()
@click.argument("key", metavar="OBJECT_KEY")
@click.argument("email")
def share(key, email):
    """Stub: Share OBJECT_KEY with another user (TODO)"""
    click.echo("[WARN] Share feature not implemented yet")

if __name__ == "__main__":
    cli()