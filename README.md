# Paw Bank 🐾🏦

A Secure and Real-Time Banking Application

![Paw Bank Logo (Replace with your actual logo if any)](https://placehold.co/200x200?text=Paw+Bank+Logo&font=Montserrat)

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
    -   [Django REST framework](https://www.django-rest-framework.org/) (version X.Y.Z - based on your dependency): Powerful toolkit for building Web APIs.
    -   [djangorestframework-simplejwt](https://github.com/jazzband/djangorestframework-simplejwt) (version 5.3.1): JWT authentication for REST APIs.
    -   [psycopg2-binary](https://pypi.org/project/psycopg2-binary/) (version 2.9.10): PostgreSQL database adapter.
-   **Real-Time:**
    -   [Channels](https://channels.readthedocs.io/en/stable/) (version 4.2.0): ASGI support and WebSockets for real-time updates.
    -   [Daphne](https://daphne.readthedocs.io/en/latest/) (version 4.1.2): HTTP/WebSocket server for ASGI.
-   **Security:**
    -   [PyOpenSSL](https://pypi.org/project/pyOpenSSL/) (version 24.3.0): Provides a set of python libraries that wraps openssl for ssl connections.
    -   [service-identity](https://pypi.org/project/service-identity/) (version 24.2.0):  Verifying TLS server identities.
-   **Other:**
    -   [django-cors-headers](https://github.com/adamchainz/django-cors-headers) (version 4.6.0): Handles Cross-Origin Resource Sharing.
    -   [python-dotenv](https://github.com/theskumar/python-dotenv) (version 1.0.1): Manages environment variables from `.env` files.
    -   [requests](https://pypi.org/project/requests/) (version 2.32.3): HTTP request library.

### Dependencies Graph

Below is a graph of our project dependencies.
