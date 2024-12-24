from django.core.management.utils  import get_random_secret_key
import os

if __name__ == '__main__':
    if not os.path.exists(".env"):
        with open(".env","w") as env_file:
            pass
    
    secret = get_random_secret_key()
    with open(".env","w") as env_file:
        env_file.write(f"\nSECRET_KEY={secret}")