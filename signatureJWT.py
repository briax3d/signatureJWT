from math import gcd
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64


#def existsABaseValue( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
#    e = 3
#    while( e < 65537 and not is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) ) ):
#        e = e + 1
#    return is_AValidBase( gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) )

def GeneratePublicKeysFromJWT_And_(firstJWT, secondJWT):
    for pair in findThePublicPairValues( *numbersOfMessageAndSignatureFromJWT_(firstJWT), *numbersOfMessageAndSignatureFromJWT_(secondJWT) ):
        ExportRSAPublicKeysWith_And_(*pair)

def ExportRSAPublicKeysWith_And_(n, e):
    with open(f'PKCS1_{n}_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=n, e=e).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1))
    with open(f'X509_{n}_{e}.pem', 'wb') as file:
        file.write(rsa.RSAPublicNumbers(n=n, e=e).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

def numbersOfMessageAndSignatureFromJWT_( jwtParts ):
    return ( int.from_bytes(f'{jwtParts[0]}.{jwtParts[1]}'.encode('utf-8'), 'big'), int.from_bytes(jwtParts[2].encode('utf-8'), 'big') )

def findThePublicPairValues( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber ):
    publicPairList = []
    for e in range(3, 65537):
        publicPairList.append(gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber)) if is_AValidBase( *gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber), firstMessageNumber, firstSignatureNumber ) else None
    return publicPairList

def is_AValidBase( gcd, e, firstMessageNumber, firstSignatureNumber ):
    return pow(firstSignatureNumber, e) % gcd == firstMessageNumber % gcd

def gcdExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
    return (gcd( pow( firstSignatureNumber, e ) - firstMessageNumber, pow( secondSignatureNumber, e ) - secondMessageNumber ), e)

################################################################################################################################################################

def generateSignature(secret, headerAndPayload):
    h = hmac.HMAC( secret.encode(), hashes.SHA256())
    h.update( headerAndPayload.encode() )
    return base64.urlsafe_b64encode( h.finalize() )

def signJWT(secret, jwt):
    splitedJWT = jwt.split('.')
    splitedJWT[2] = generateSignature(secret, f'{splitedJWT[0]}.{splitedJWT[1]}').decode()
    return '.'.join(splitedJWT)

print( signJWT('', 'a.b.c') )
