from math import gcd
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
import json
import base64

def existsABaseValue( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
    e = 3
    while( e < 65537 and not is_AValidBase( gdmExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) ) ):
        e = e + 1
    return is_AValidBase( gdmExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) )

def findTheBasesValues( firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber ):
    e = 3
    while( e < 65537 and not is_AValidBase( gdmExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber) ) ):
        e = e + 1
        gdmExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber)

def is_AValidBase( number ):
    return False

def gdmExponent_Between_With_And_With_(e, firstMessageNumber, firstSignatureNumber, secondMessageNumber, secondSignatureNumber):
    return gdm( pow( firstSignatureNumber, e ) - firstMessageNumber, pow( secondSignatureNumber, e ) - secondMessageNumber )

def generateSignature(secret, headerAndPayload):
    h = hmac.HMAC( secret.encode(), hashes.SHA256())
    h.update( headerAndPayload.encode() )
    return base64.urlsafe_b64encode( h.finalize() )

def signJWT(secret, jwt):
    splitedJWT = jwt.split('.')
    splitedJWT[2] = generateSignature(secret, f'{splitedJWT[0]}.{splitedJWT[1]}').decode()
    return '.'.join(splitedJWT)

print( signJWT('', 'a.b.c') )
