from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from gmpy2 import gcd, mpz, c_div, powmod
from pwn import log
import base64
import sys

info, counter = (None, None)

#def existsABaseValue( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
#    e = 3
#    while( e < 65537 and not is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) ) ):
#        e = e + 1
#    return is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) )

def digestOfMessageFrom_JWTPartsWith_Algorithm( jwtParts, alg ):
    h = hashes.Hash( alg )
    h.update( f'{jwtParts[0]}.{jwtParts[1]}'.encode('ascii') )
    return h.finalize()

def GeneratePublicKeysFromJWT_And_(firstJWT, secondJWT):
    CreatePublicKeysGenerateProgressBars()
    for pair in findThePublicPairValues( *numbersOfMessageAndSignatureFromJWT_(firstJWT.split('.')), *numbersOfMessageAndSignatureFromJWT_(secondJWT.split('.')) ):
        ExportRSAPublicKeysWith_And_(*pair)

def ExportRSAPublicKeysWith_And_(n, e):
    global info
    info.status("exporting rsa public keys...")
    with open(f'PKCS1_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=int(n), e=int(e)).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1))
    with open(f'X509_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=int(n), e=int(e)).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

def numbersOfMessageAndSignatureFromJWT_( jwtParts ):
    global info
    info.status("obtaining JWS message and signature numbers...")
    signature = base64.urlsafe_b64decode(jwtParts[2] + "=" * (len(jwtParts[2]) % 4) ) # b64 strings must have a 4 multiple length
    message = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE( SHA256.new( f'{jwtParts[0]}.{jwtParts[1]}'.encode('ascii') ), len(signature) ) # adds the neccessary padding
    return ( mpz(int.from_bytes(message, 'big')), mpz(int.from_bytes(signature, 'big')) )

def findThePublicPairValues( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber ):
    global info, counter
    info.status("finding public key pair values...")
    publicPairList = []
    for e in [3, 65537]:
        publicPairList = publicPairList + publicPairListFor_Exponent_And_NumbersWith_And_NumbersFor_GCD(mpz(e), firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber, gcdExponent_Between_With_And_With_(mpz(e), firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber))
        counter.status(len(publicPairList))
    return publicPairList

def publicPairListFor_Exponent_And_NumbersWith_And_NumbersFor_GCD(e, firstMessage, firstSignature, secondMessage, secondSignature, gcd):
    global info
    n_values = []
    info.status(f"finding public key pair values for exponent {e}...")
    for number in range(1,100):
        type(number)
        info.status(f"finding public key pair values for exponent {e} and divisor {number}...")
        n_values.append( (c_div( gcd[0], mpz(number) ), e) ) if is_AValidBase( c_div(gcd[0], mpz(number) ), e, firstMessage, firstSignature ) else None
    return n_values

def is_AValidBase( n, e, firstMessageNumber, firstSignatureNumber ):
    return n != 0 and e % 2 != 0 and powmod(firstSignatureNumber, e, n) == firstMessageNumber

def gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
    return ( gcd( pow( firstSignatureNumber, e ) - firstMessageNumber, pow( secondSignatureNumber, e ) - secondMessageNumber ), e)

################################################################################################################################################################

def generateSignature(secret, headerAndPayload):
    h = hmac.HMAC( secret.encode(), hashes.SHA256())
    h.update( headerAndPayload.encode() )
    return base64.urlsafe_b64encode( h.finalize() )

def signJWT(secret, jwt):
    splitedJWT = jwt.split('.')
    splitedJWT[2] = generateSignature(secret, f'{splitedJWT[0]}.{splitedJWT[1]}').decode()
    return '.'.join(splitedJWT)

def CreatePublicKeysGenerateProgressBars():
    global info, counter
    info = log.progress('status')
    counter = log.progress("n values counter")
    info.status('...')
    counter.status('...')

if __name__ == '__main__':
    GeneratePublicKeysFromJWT_And_(sys.argv[1], sys.argv[2])
