# Cryptography
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# My
from . import utility

import traceback

class FernetCryptographyClass:
    
    def __init__(self, _password, _salt, _value):
        
        # Defaults
        self.algo       = 'Scrypt'
        self.encoding   = 'UTF-8'
        self.backend    = default_backend()
        
        # Inputs
        self.password_encoded   = _password.encode(self.encoding)
        self.salt_encoded       = _salt.encode(self.encoding)
        self.value              = _value
        
        # Prepare
        self.response_tuple = None
        self.inputs         = f"{_salt}|{_value}"
        self.output_value   = None

    """""""""""""""""""""""""""""""""""""""""""""
    Verify if _string is encoded
    """""""""""""""""""""""""""""""""""""""""""""
    def is_encoded(self, _string):
        import chardet
        try:
            b = chardet.detect(_string)
            return(True)
        except:
            return(False)


    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Create Fernet Obj with the given PASSWORD and SALT
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def create_fernet_obj(self):
        
        # PBKDF2 (Password Based Key Derivation Function 2)
        if (self.algo == 'PBKDF2'):
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes 
            kdf = PBKDF2HMAC(   algorithm   = hashes.SHA256(),
                                length      = 32,
                                salt        = self.salt_encoded,
                                iterations  = 100000,
                                backend     = self.backend
                            )
        # SCRYPT is a KDF designed for password storage by Colin Percival to be resistant 
        # against hardware-assisted attackers by having a tunable memory cost
        if (self.algo == 'Scrypt'):
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
            kdf = Scrypt(   salt    = self.salt_encoded,
                            length  = 32,
                            n       = 2**14,
                            r       = 8,
                            p       = 1,
                            backend = self.backend
                    )
        
        # Derive --> create fernet token
        try:
            _f_key              = base64.urlsafe_b64encode( kdf.derive( self.password_encoded ) )
            self.response_tuple = ('OK',_f_key)
        except:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','FernetCryptographyClass.create_fernet_obj',self.inputs,traceback.format_exc(2))}")
            
        # Instance Fernet Obj
        try:
            _fernet_obj         = Fernet(_f_key)
            self.response_tuple = ('OK',_fernet_obj)
        except:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','FernetCryptographyClass.create_fernet_obj',self.inputs,traceback.format_exc(2))}")
            
        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    CRYPT (symmetric encryption with fernet token created from given PASSWORD and SALT)
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def crypt(self):
        
        # Create Obj
        _fernet_obj  = self.create_fernet_obj()
        
        # Crypt with Fernet Obj
        if _fernet_obj[0] == 'OK':

            if not ( self.is_encoded(self.value)  ):
                try:
                    self.output_value   = _fernet_obj[1].encrypt( self.value.encode(self.encoding) )
                    self.response_tuple = ('OK',self.output_value)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','FernetCryptographyClass.crypt',self.inputs,traceback.format_exc(2))}")
            else:
                try:
                    self.output_value   = _fernet_obj[1].encrypt( self.value )
                    self.response_tuple = ('OK',self.output_value)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','FernetCryptographyClass.crypt',self.inputs,traceback.format_exc(2))}")
        
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','FernetCryptographyClass.crypt',self.inputs,_fernet_obj[1])}")
        
        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    DECRYPT (symmetric encryption with fernet token created from given PASSWORD and SALT)
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def decrypt(self):
        
        # Create Obj
        _fernet_obj  = self.create_fernet_obj()

        # Decrypt with Fernet Obj
        if _fernet_obj[0] == 'OK':
            
            if ( self.is_encoded(self.value) ):
                try:
                    self.output_value   = str(_fernet_obj[1].decrypt( self.value ), self.encoding )
                    self.response_tuple = ('OK',self.output_value)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','FernetCryptographyClass.decrypt',self.inputs,traceback.format_exc(2))}")
            else:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Error','FernetCryptographyClass.decrypt',self.inputs,'Input value not encoded')}")

        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','FernetCryptographyClass.decrypt',self.inputs,_fernet_obj[1])}")

        return(self.response_tuple)
