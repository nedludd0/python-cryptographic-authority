# Cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidKey, InvalidSignature

# Others
import base64
import traceback
import os.path

# My
import utility

class PyCaClass:
    
    def __init__(self, _salt):
        
        # Defaults
        self.algo               = 'Scrypt'
        self.encoding           = 'UTF-8'
        self.backend            = default_backend()
        
        # Inputs
        self.salt           = f"{_salt}"
        self.salt_encoded   = self.salt.encode(self.encoding) + self.salt.encode(self.encoding) # I double the salt to make the encryption more robust

        # Prepare
        self.inputs                 = f"{_salt}|{self.algo}|{self.encoding}"        
        self.response_tuple         = None
        self.input_value_encoded    = None
        self.input_value_crypted    = None
        self.input_value_decrypted  = None
        self.output_value_decoded   = None        

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
                self.response_tuple = ('OK', kdf)
                
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
                self.response_tuple = ('OK', kdf)
                
            except:
                self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_kdf',self.inputs,traceback.format_exc(2))}")

        
        return(self.response_tuple)
        
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Derived Key from the given PASSWORD and SALT - like HASHING password
    """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    def derive_and_b64encode_key(self, _password2hash):
        
        # Prepare
        _kdf_derive                 = None
        _f_key_b64encode            = None
        self.input_value_encoded    = _password2hash.encode(self.encoding)        
        
        # Create KDF
        _kdf = self.create_kdf()
        
        # Derive (Hashing)
        if _kdf[0] == 'OK':
            try:
                _kdf_derive                 = _kdf[1].derive( self.input_value_encoded )
                _f_key_b64encode            =  base64.urlsafe_b64encode(_kdf_derive)
                self.output_value_decoded   = str(_f_key_b64encode, self.encoding )
                self.response_tuple         = ('OK', self.output_value_decoded)
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
        self.input_value_encoded    = _password2verify.encode(self.encoding)
        _password_stored_b64decode  = base64.urlsafe_b64decode(_password_stored) # b64decode
         
        # Create KDF
        _kdf = self.create_kdf()
        
        # Instance Fernet Obj
        if _kdf[0] == 'OK':
            try:
                _kdf[1].verify(self.input_value_encoded, _password_stored_b64decode)
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
                _fernet_obj         = Fernet( _f_key[1] )
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
                    self.input_value_encoded    = _input_value1.encode(self.encoding)
                    self.input_value_crypted    = _fernet_obj[1].encrypt(self.input_value_encoded)
                    self.output_value_decoded   = str(self.input_value_crypted, self.encoding)
                    self.response_tuple         = ('OK',self.output_value_decoded)
                except:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.crypt',_inputs,traceback.format_exc(2))}")
            else:
                try:
                    self.input_value_crypted    = _fernet_obj[1].encrypt( _input_value1 )
                    self.output_value_decoded   = str( self.input_value_crypted, self.encoding )
                    self.response_tuple         = ('OK',self.output_value_decoded)
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
            
            if not ( self.is_encoded(_input_value1) ):
                try:
                    self.input_value_encoded    = _input_value1.encode(self.encoding)
                    self.input_value_decrypted  = _fernet_obj[1].decrypt(self.input_value_encoded)
                    self.output_value_decoded   = str( self.input_value_decrypted, self.encoding )
                    self.response_tuple         = ('OK',self.output_value_decoded)
                except InvalidToken:
                    self.response_tuple         = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_fernet_obj',_inputs,'Wrong password for decrypt')}")                                                             
                except Exception:
                    self.response_tuple         = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.decrypt',_inputs,traceback.format_exc(2))}")
            else:
                try:
                    self.input_value_decrypted  = _fernet_obj[1].decrypt(_input_value1)
                    self.output_value_decoded   = str( self.input_value_decrypted, self.encoding )
                    self.response_tuple         = ('OK',self.output_value_decoded)
                except InvalidToken:
                    self.response_tuple         = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.create_fernet_obj',_inputs,'Wrong password for decrypt')}")                                                             
                except Exception:
                    self.response_tuple         = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.decrypt',_inputs,traceback.format_exc(2))}")

        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.decrypt',_inputs,_fernet_obj[1])}")

        return(self.response_tuple)

    """""""""""""""""""""""""""""""""""""""
    CHECKSUM file ( SHA256 or BLAKE2b )
    """""""""""""""""""""""""""""""""""""""
    def checksum_file(self, _algo2checksum, _file_path, _file_name):
        
        # Prepare
        _file               = f"{_file_path}{_file_name}"
        _inputs             = f"{self.inputs}|{_algo2checksum}|{_file}"
        _checksum           = None
        _checksum_b64encode = None
        
        # Choose Algorithm
        if _algo2checksum.lower() == 'sha256':
            _algo_checksum_file = hashes.SHA256()
        elif _algo2checksum.lower() == 'blake2':
            _algo_checksum_file = hashes.BLAKE2b(64)
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.checksum_file',_inputs,'Unknown algorithm')}")
            return(self.response_tuple)
            
        if os.path.exists(_file):
        
            with open(_file, "rb") as f:
                try:
                    _file_hash = hashes.Hash( _algo_checksum_file, backend=self.backend )
                    while chunk := f.read(8192): # Read the binary file to the end (8192)
                        _file_hash.update(chunk)
                except Exception:
                    self.response_tuple = ('NOK',  f"{ utility.my_log('Exception','PyCaClass.checksum_file',_inputs,traceback.format_exc(2))}")

            _checksum                   = _file_hash.finalize()
            _checksum_b64encode         = base64.urlsafe_b64encode(_checksum )
            self.output_value_decoded   = str(_checksum_b64encode, self.encoding)
            self.response_tuple         = ('OK',self.output_value_decoded)
            
        else:
            self.response_tuple = ('NOK',  f"{ utility.my_log('Error','PyCaClass.checksum_file',_inputs,'File does not exist')}")
            
        return(self.response_tuple)

