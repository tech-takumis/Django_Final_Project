from  cryptography.fernet import Fernet
from django.core.management.utils import get_random_secret_key
import os

def generate_fernet_key():
    key = Fernet.generate_key()
    print(f"Generate Fernet Key:\n{key.decode()}")
    return key.decode()

if __name__ == '__main__':

    if not os.path.exists(".env"):
            with open(".env", "w") as env_file:
                    pass
            
    key = generate_fernet_key()
    secret = get_random_secret_key()
    with open(".env", "a") as env_file:
            env_file.write(f"\nENCRYPTION_KEY={key}")
            env_file.write(f"SECRET_KEY={secret}")