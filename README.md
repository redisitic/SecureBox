# SecureBox – client‑side encrypted Dropbox‑style CLI

## Minimal proof‑of‑concept for the mini‑project:
* AES‑256‑GCM client‑side encryption
* Optional AWS KMS envelope keys, or locally stored master key
* Upload / download files to an S3 bucket via boto3

## Dependencies:
    pip install boto3 cryptography click python-dotenv

## Environment (create a .env file or export these):
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
    SECUREBOX_BUCKET       – S3 bucket name
    SECUREBOX_MASTER_KEY   – 64‑hex chars (if not using KMS)
    SECUREBOX_KMS_KEY_ID   – arn:aws:kms:... (optional)
