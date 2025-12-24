FROM python:3.11-slim

WORKDIR /app

RUN apt update -y && apt install python3-dev python3 -y
RUN python3 -m pip install pycryptodome cryptography pwntools gmpy2
                                                 

