# signatureJWT
A Python3 script for deriving the "n" value of the RSA public key from two JWS tokens.

## How does it work?
It calculates the greatest common divisor (gcd) between the integer signatures values:
```python3
# SNIP
return ( gcd( pow( firstSignatureNumber, e ) - firstMessageNumber, pow( secondSignatureNumber, e ) - secondMessageNumber ), e)
```
It verifies _n_ values by checking if the integer values for the signature raised to an _e_ value, divided by the _n_ value, have a module that is equal to the message integer value ("message" value is composed by the header and payload JWT parts).

Here is a snipet of code used for the previous purpose:
```python
# SNIP
return n != 0 and e % 2 != 0 and powmod(firstSignatureNumber, e, n) == firstMessageNumber
```
As you can see, it also verifies if the _n_ value is different from zero, and if _e_ is an odd number.

As the _gcd_ value could possible be a _n_ multiple instead of being the actual value of _n_, we must divide the _gcd_ value by a range of integer values, as assume those as the the _n_ values to validate.

[Information about used gmpy2 functions can be found here](<https://gmpy2.readthedocs.io/en/latest/mpz.html#mpz-type>)

## How can I use it?
The repository has a _Dockerfile_, which is prepared for resolving the script dependencies.

I personally recommend runing the following one-liner, so you can build and run a docker environment within you will be able to run "signatureJWT.py" script without any dependency issues:
```bash
docker build -t signature . ; docker run --rm -v $(pwd):/app -it signature /bin/bash
```

Once insede docker interactive terminal, you will need to run the python3 script, so you will need to pass two JWTs as the arguments of the script. The arguments must be passed to the script in the following way:
```bash
python3 signatureJWT.py <fist-token> <second-token>
```

# References
This script is based on the following references:

- [https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/](<https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/>)
- [https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301](<https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301>)
- [https://portswigger.net/web-security/jwt/algorithm-confusion](<https://portswigger.net/web-security/jwt/algorithm-confusion>)
