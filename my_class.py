# Cryptography
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from cryptography.exceptions import InvalidKey, InvalidSignature


# My
import utility

import traceback

class PyCaClass:
    
    def __init__(self, _salt):
        
        # Defaults
        self.algo           = 'Scrypt'
        self.encoding       = 'UTF-8'
        self.backend        = default_backend()
        
        # Inputs
        self.salt_encoded   = _salt.encode(self.encoding) + _salt.encode(self.encoding) # I double the salt to make the encryption more robust

        # Prepare
        self.response_tuple = None
        self.output_value   = None
        self.inputs         = f"{_salt}|{self.algo}|{self.encoding}"

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


    """""""""""""""""""""""""""""""""""""""""""""""""""
    Create KDF the given PASSWORD and SALT
    """""""""""""""""""""""""""""""""""""""""""""""""""
    def create_kdf(self):
        
        # PBKDF2 (Password Based Key Derivation Function 2)
        if (self.algo == 'PBKDF2'):
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            try:
                kdf = PBKDF2HMAC(   algorithm   = hashes.SHA256(),
                                    length      = 32,
                                    salt        = self.salt_encoded,
                                    iterations  = 100000,
                                    backend     = self.backend  )
                self.response_tuple = ('OK',kdf)
                
            except:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_kdf',self.inputs,traceback.format_exc(2))}")

        # SCRYPT is a KDF designed for password storage by Colin Percival to be resistant 
        # against hardware-assisted attackers by having a tunable memory cost
        if (self.algo == 'Scrypt'):
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

            try:
                kdf = Scrypt(   salt    = self.salt_encoded,
                                length  = 32,
                                n       = 2**14,
                                r       = 8,
                                p       = 1,
                                backend = self.backend  )
                self.response_tuple = ('OK',kdf)
                
            except:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_kdf',self.inputs,traceback.format_exc(2))}")

        
        return(self.response_tuple)
        
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Derived Key from the given PASSWORD and SALT - like HASHING password
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def derive_and_b64encode_key(self, _password2hash):
        
        # Prepare
        _password2hash_encoded  = _password2hash.encode(self.encoding)
        
        # Create KDF
        _kdf = self.create_kdf()
        
        # Derive (Hashing)
        if _kdf[0] == 'OK':
            try:
                _f_derive   = _kdf[1].derive( _password2hash_encoded )
                _f_key      = base64.urlsafe_b64encode(_f_derive)
                self.response_tuple = ('OK',_f_key)
            except:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.derive_and_b64encode_key',self.inputs,traceback.format_exc(2))}")
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.derive_and_b64encode_key',self.inputs,_kdf[1])}")

        return(self.response_tuple)
            
    """""""""""""""""""""""""""""""""""""""""""""""""""
    VERIFY the password with its derived key (your hash)
    """""""""""""""""""""""""""""""""""""""""""""""""""
    def verify_password(self, _password_stored, _password2verify):
    
        # Prepare
        _inputs                     = f"{self.inputs}|{_password_stored}|{_password2verify}"
        _password2verify_encoded    = _password2verify.encode(self.encoding)
        _password_stored_b64decode  = base64.urlsafe_b64decode(_password_stored) # b64decode
         
        # Create KDF
        _kdf = self.create_kdf()
        
        # Instance Fernet Obj
        if _kdf[0] == 'OK':
            try:
                _kdf[1].verify(_password2verify_encoded, _password_stored_b64decode)
                self.response_tuple = ('OK', True)
            except InvalidKey as e:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.verify_password',_inputs,e)}")
            except Exception:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.verify_password',_inputs,traceback.format_exc(2))}")
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.verify_password',_inputs,_kdf[1])}")
        
        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""""""""""""""
    Create Fernet Obj from derived key
    """""""""""""""""""""""""""""""""""""""""""""""""""
    def create_fernet_obj(self, _password2hash):
        
        _f_key = self.derive_and_b64encode_key(_password2hash)
       
        # Instance Fernet Obj
        if _f_key[0] == 'OK':
            try:
                _fernet_obj = Fernet( _f_key[1] )
                self.response_tuple = ('OK',_fernet_obj)              
            except:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_fernet_obj',self.inputs,traceback.format_exc(2))}")
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.create_fernet_obj',self.inputs,_f_key[1])}")
            
        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    CRYPT symmetric encryption of _input_value1 (with fernet obj)
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def crypt(self, _password4crypt, _input_value1):
        
        # Prepare
        _inputs = f"{self.inputs}|{_input_value1}"
        
        # Create Obj
        _fernet_obj  = self.create_fernet_obj(_password4crypt)
        
        # Crypt with Fernet Obj
        if _fernet_obj[0] == 'OK':

            if not ( self.is_encoded(_input_value1)  ):
                try:
                    self.output_value   = _fernet_obj[1].encrypt( _input_value1.encode(self.encoding) )
                    self.response_tuple = ('OK',self.output_value)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.crypt',_inputs,traceback.format_exc(2))}")
            else:
                try:
                    self.output_value   = _fernet_obj[1].encrypt( _input_value1 )
                    self.response_tuple = ('OK',self.output_value)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.crypt',_inputs,traceback.format_exc(2))}")
        
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.crypt',_inputs,_fernet_obj[1])}")
        
        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    DECRYPT symmetric encryption of _input_value1 (with fernet obj)
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def decrypt(self, _password4decrypt, _input_value1):

        # Prepare
        _inputs = f"{self.inputs}|{_input_value1}"
        
        # Create Obj
        _fernet_obj  = self.create_fernet_obj(_password4decrypt)

        # Decrypt with Fernet Obj
        if _fernet_obj[0] == 'OK':
            
            if self.is_encoded(_input_value1):
                try:
                    self.output_value   = str( _fernet_obj[1].decrypt( _input_value1 ), self.encoding )
                    self.response_tuple = ('OK',self.output_value)
                except InvalidToken:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_fernet_obj',_inputs,'InvalidToken')}")                                                             
                except Exception:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.decrypt',_inputs,traceback.format_exc(2))}")
            else:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.decrypt',_inputs,'Input value not encoded')}")

        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.decrypt',_inputs,_fernet_obj[1])}")

        return(self.response_tuple)
