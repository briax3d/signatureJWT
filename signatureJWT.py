from math import gcd
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
import base64
import sys


#def existsABaseValue( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
#    e = 3
#    while( e < 65537 and not is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) ) ):
#        e = e + 1
#    return is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) )

def GeneratePublicKeysFromJWT_And_(firstJWT, secondJWT):
    for pair in findThePublicPairValues( *numbersOfMessageAndSignatureFromJWT_(firstJWT), *numbersOfMessageAndSignatureFromJWT_(secondJWT) ):
        ExportRSAPublicKeysWith_And_(*pair)

def ExportRSAPublicKeysWith_And_(n, e):
    with open(f'PKCS1_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=n, e=e).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1))
    with open(f'X509_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=n, e=e).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

def numbersOfMessageAndSignatureFromJWT_( jwtParts ):
    message = int.from_bytes( pkcs1_15._EMSA_PKCS1_V1_5_ENCODE( hashes.Hash(hashes.SHA256()).update( f'{jwtParts[0]}.{jwtParts[1]}'.encode('ascii') ) ), 'big' ) # adds the neccessary padding
    signature = int.from_bytes( base64.urlsafe_b64decode(jwtParts[2] + '=' * (len(jwtParts[2]) % 4)), 'big' ) # b64 strings must have a 4 multiple length
    return (message, signature)

def findThePublicPairValues( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber ):
    publicPairList = []
    for e in [3, 65537]:
        publicPairList = publicPairList + publicPairListFor_Exponent_And_NumbersWith_And_NumbersFor_GCD(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber, gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber))
    return publicPairList

def publicPairListFor_Exponent_And_NumbersWith_And_NumbersFor_GCD(e, firstMessage, firstSignature, secondMessage, secondSignature, gcd):
    n_values = []
    for number in range(1,100):
        n_values.append( gcd // number ) if is_AValidBase( gcd // number, e, firstMessage, firstSignature ) else None
    return n_values

def is_AValidBase( gcd, e, firstMessageNumber, firstSignatureNumber ):
    return pow(firstSignatureNumber, e) % gcd == firstMessageNumber and e % 2 != 0

def gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
    return gcd( pow( firstSignatureNumber, e ) - firstMessageNumber, pow( secondSignatureNumber, e ) - secondMessageNumber )

################################################################################################################################################################

def generateSignature(secret, headerAndPayload):
    h = hmac.HMAC( secret.encode(), hashes.SHA256())
    h.update( headerAndPayload.encode() )
    return base64.urlsafe_b64encode( h.finalize() )

def signJWT(secret, jwt):
    splitedJWT = jwt.split('.')
    splitedJWT[2] = generateSignature(secret, f'{splitedJWT[0]}.{splitedJWT[1]}').decode()
    return '.'.join(splitedJWT)
print(__name__)
#if __name__ == '__main__':
#    GeneratePublicKeysFromJWT_And_(sys.argv[1], sys.argv[2])
