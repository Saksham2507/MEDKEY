import sys
sys.path.insert(0, '.')
from phase3_asymmetric.asymmetric_engine import sign_challenge

nonce = "REPLACE_WITH_FRESH_NONCE"

private_key = b"""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgxfVS2JfR1racudeqWNtV
uDNY2N4HwxBRyXxS3hOtYDOhRANCAATuOmh++uRljzl2ojqAxXtwUJ6yVYfZbXNj
sdWPWQjQqaRQVjGbBiFg1NMdh+35uapgQRMuH+Nnmwkoohqc79s1
-----END PRIVATE KEY-----"""

signature = sign_challenge(nonce, private_key)
print("SIGNATURE:", signature)