#Paw Bank <img src="https://private-user-images.githubusercontent.com/156514426/398561049-b917a6da-f9b3-4c0c-acce-3d46f7a686ba.svg?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzUxMjE3MzYsIm5iZiI6MTczNTEyMTQzNiwicGF0aCI6Ii8xNTY1MTQ0MjYvMzk4NTYxMDQ5LWI5MTdhNmRhLWY5YjMtNGMwYy1hY2NlLTNkNDZmN2E2ODZiYS5zdmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMjI1JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTIyNVQxMDEwMzZaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xYzQ0YWRmZTkzZWFlM2ZhYjUwODY4Zjg3Yzg4Y2I3N2JmZTdhYmIxZjAxNGIwODA4NjQ1ODBlNzIwZWU2ZmM0JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.gAT2DIAzqShc5CgH0zER1OfOJDgyLM_VaLpG8tLnneE" alt="paw-bank" style="max-width: 100%; width: 25px;">

A Secure and Real-Time Banking Application

<img src="https://private-user-images.githubusercontent.com/156514426/398561049-b917a6da-f9b3-4c0c-acce-3d46f7a686ba.svg?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzUxMjE3MzYsIm5iZiI6MTczNTEyMTQzNiwicGF0aCI6Ii8xNTY1MTQ0MjYvMzk4NTYxMDQ5LWI5MTdhNmRhLWY5YjMtNGMwYy1hY2NlLTNkNDZmN2E2ODZiYS5zdmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMjI1JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTIyNVQxMDEwMzZaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xYzQ0YWRmZTkzZWFlM2ZhYjUwODY4Zjg3Yzg4Y2I3N2JmZTdhYmIxZjAxNGIwODA4NjQ1ODBlNzIwZWU2ZmM0JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.gAT2DIAzqShc5CgH0zER1OfOJDgyLM_VaLpG8tLnneE" alt="paw-bank" style="max-width: 100%; width: 300px;">


## Overview

Paw Bank is a modern web application designed to facilitate secure and real-time fund transfers between users. Built with Django, Django REST framework, and Channels, it offers a seamless and responsive banking experience. This repository contains the codebase for the Paw Bank application, including the backend API and WebSocket functionalities for live updates.

## Key Features

-   **Secure Fund Transfers:** Encrypted transfers between users using secure API endpoints.
-   **Real-Time Notifications:** Instant updates on transactions via WebSockets.
-   **User Authentication:** Secure user registration, login, and token-based authentication.
-   **API Driven Architecture:** Built with Django REST framework, making it easy to integrate with other applications.
-   **Modern Design:** A user-friendly and responsive interface.

## Technologies Used

This project leverages the following technologies and packages:

-   **Backend:**
    -   [Django](https://www.djangoproject.com/) (version 5.1.4): High-level Python Web framework for rapid development.
    -   [Django REST framework](https://www.django-rest-framework.org/) (version 3.15.2 - based on your dependency): Powerful toolkit for building Web APIs.
    -   [djangorestframework-simplejwt](https://github.com/jazzband/djangorestframework-simplejwt) (version 5.3.1): JWT authentication for REST APIs.
    -   [psycopg2-binary](https://pypi.org/project/psycopg2-binary/) (version 2.9.10): PostgreSQL database adapter.
-   **Real-Time:**
    -   [Channels](https://channels.readthedocs.io/en/stable/) (version 4.2.0): ASGI support and WebSockets for real-time updates.
    -   [Daphne](https://daphne.readthedocs.io/en/latest/) (version 4.1.2): HTTP/WebSocket server for ASGI.
-   **Security:**
    -   [PyOpenSSL](https://pypi.org/project/pyOpenSSL/) (version 24.3.0): Provides a set of python libraries that wraps openssl for ssl connections.
    -   [service-identity](https://pypi.org/project/service-identity/) (version 24.2.0):  Verifying TLS server identities.
    -   [Cryptography](https://pypi.org/project/cryptography/) (version 44.0.0.): Cryptography’s high level symmetric encryption
-   **Other:**
    -   [django-cors-headers](https://github.com/adamchainz/django-cors-headers) (version 4.6.0): Handles Cross-Origin Resource Sharing.
    -   [python-dotenv](https://github.com/theskumar/python-dotenv) (version 1.0.1): Manages environment variables from `.env` files.
    -   [requests](https://pypi.org/project/requests/) (version 2.32.3): HTTP request library.


## Installation

Follow these steps to set up the Paw Bank application on your local machine:

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/tech-takumis/Django_Final_Project.git
    cd paw-bank
    ```

2.  **Install Pipenv (if you don't have it):**

    ```bash
    pip install pipenv
    ```

3. **Navigate to project1 and project2 folder.**

    ```bash
      cd project1
    ```

    ```bash
      cd ../project2
    ```
4.  **Activate the Pipenv virtual environment**

    ```bash
    pipenv shell
    ```
5.  **Install dependencies in both project1 and project2:**

    ```bash
    pipenv install
    ```
6.  **Generate `.env` files and Keys:**

    -   Navigate to the root of `project2` and run the key generation script:

        ```bash
        cd project2
        python generate_key.py
        ```
        This will create `.env` file with necessary configurations, including `ENCRYPTION_KEY` and `JWT_SIGNING_KEY`.
         -   Navigate to the root of `project1` and run the key generation script:

        ```bash
        cd ../project1
        python generate_key.py
        ```
        This will create `.env` file with necessary configurations, including `SECRET_KEY`.

    -   **Important:** After generating keys for `project2`, you need to copy the following keys from `project2/.env` to `project1/.env`:

        -   `ENCRYPTION_KEY`
        -   `JWT_SIGNING_KEY`

        This ensures that both Project 1 and Project 2 use the same keys for cryptography and JWT, enabling the proper transfer of data between them.

7. **Navigate back to project2 and Apply migrations:**
    ```bash
        cd ../project2
        python manage.py migrate
    ```
8.  **Create super user**
      ```bash
        python manage.py createsuperuser
      ```
9.  **Run the development server in project1 and project2:**
    
    -   For `project1`:

       ```bash
       cd ../project1
       python manage.py runserver 0.0.0.0:8000
       ```
    -   For `project2`:

       ```bash
       cd ../project2
       python manage.py runserver 0.0.0.0:8001
       ```
## Paw Bank System architecture


![Paw Bank System Architecture](https://github.com/user-attachments/assets/ea0c86ef-8aae-4da2-a8e4-0a82bf4c9165)
