# this module handles the secure functions for the app
import bcrypt


def getSalt():
    salt = bcrypt.gensalt()
    return salt


def hashpassword(password, salt):
    # converting password to array of bytes
    bytes = password.encode("utf-8")

    # Hashing the password
    hash = bcrypt.hashpw(bytes, salt)
    return hash
