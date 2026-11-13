"""Fake credentials for tests.

Values are assembled from pieces so this repository never contains a
literal that a secret scanner (including this one) would flag. None of
them are real; the AWS ones are Amazon's documented example values.
"""

AWS_KEY_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
OPENSSH_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
JWT = ".".join(
    [
        "eyJ" + "hbGciOiJIUzI1NiJ9",
        "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]
)
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SLACK_TOKEN = "xox" + "b-" + "123456789012-abcdefghijkl"
GOOGLE_KEY = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
STRIPE_KEY = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
RANDOM_TOKEN = "Zx8Qp2Lm9Vt4" + "Rk7Wn3Yb6Hc1Jd5Fg0Ks"
