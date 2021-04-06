""" KDF """
# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt

""" AES256 """
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption.html?highlight=aes#cryptography.hazmat.primitives.ciphers.Cipher
# https://gist.github.com/brysontyrrell/7cebfb05105c25d00e84ed35bd821dfe

""" SHA256 """
##### https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes


# Cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.exceptions import InvalidKey, InvalidSignature

# General
import base64
import os.path
import chardet
import binascii

# Logs
import traceback
import inspect

# My
import utility

class PyCaClass:
    
    def __init__(self, p_salt = None):
        
        # DEFAULTS
        self.encoding = 'UTF-8' # 'latin-1'
        self.backend = default_backend()
        self.kdf_algo = 'Scrypt'

        # SALT - double input to make the encryption more robust
        if utility.is_filled(p_salt):
            self.salt_string = f"{p_salt}"
            self.salt_byte = self.byte_representation('to_bin', self.salt_string) + self.byte_representation('to_bin', self.salt_string)
        else:
            self.salt_string = None
            self.salt_byte = None

        # INPUTS
        self.inputs = f"{self.encoding}|{self.salt_string}|{self.kdf_algo}"


    """""""""""""""""""""""""""""""""""""""""""""
    UTILITY
    """""""""""""""""""""""""""""""""""""""""""""

    ## Verify if _string is encoded
    def is_byte(self, p_input):
        try:
            b = chardet.detect(p_input)
            return True
        except:
            return False

    ## Generate Random Binary Data 
    # --> this function returns random bytes suitable for cryptographic use
    def generate_random_binary_data(self, _size = 32):
        _random_bytes = None
        _random_bytes = os.urandom(_size)
        return _random_bytes

    ## BINARY representation to_bin/from_bin
    def byte_representation(self, p_what, p_input):
        # Prepare
        _output = None
        # Work
        if p_what == 'to_bin':
            if not self.is_byte(p_input):
                # GET BYTES REPRESENTATION OF p_input
                _output = p_input.encode(self.encoding)
        elif p_what == 'from_bin':
            # GET STRING REPRESENTATION OF p_input
            _output = str(p_input, self.encoding)

        return _output

    ## HEX representation to_hex/from_hex
    def hex_representation(self, p_what, p_input):
        # Prepare
        _input_byte = None
        _output = None
        # Work
        if p_what == 'to_hex':
            # RETURN HEX REPRESENTATION OF p_input ONLY BINARY
            # Return the hexadecimal representation of the binary data. Every byte of data is converted into the corresponding 2-digit hex representation. 
            # The returned bytes object is therefore twice as long as the length of data.              
            if self.is_byte(p_input):
                _output = binascii.hexlify(p_input)
            else:
                _input_byte = self.byte_representation('to_bin', p_input)
                _output = binascii.hexlify(_input_byte)
        elif p_what == 'from_hex':
            # RETURN ORIGINAL DATA OF A HEX REPRESENTATION OF p_input BINARY or STRING
            _output = binascii.unhexlify(p_input)      
        # HEXLIFY and UNHEXLIFY return always a BINARY
        return _output


    """""""""""""""""""""""""""""""""""""""""""""
    KDF ( Key Derivation Function )
    """""""""""""""""""""""""""""""""""""""""""""

    ## Create KDF the given PASSWORD and SALT
    def __kdf_create(self):
        
        # Prepare
        _inputs = f"{self.inputs}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name          
        _response_tuple = None
        _msg = None
        _kdf = None

        # PBKDF2 (Password Based Key Derivation Function 2)
        if (self.kdf_algo == 'PBKDF2'):
            try:
                _kdf = PBKDF2HMAC(  algorithm = hashes.SHA256(),
                                    length = 32,
                                    salt = self.salt_byte,
                                    iterations = 100000,
                                    backend = self.backend  )
                _response_tuple = ('OK', _kdf)
            except:
                _msg = traceback.format_exc(2)
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg,False)}")

        # SCRYPT is a KDF designed for password storage by Colin Percival to be resistant 
        # against hardware-assisted attackers by having a tunable memory cost
        if (self.kdf_algo == 'Scrypt'):
            try:
                _kdf = Scrypt(  salt = self.salt_byte,
                                length = 32,
                                n = 2**14,
                                r = 8,
                                p = 1,
                                backend = self.backend  )
                _response_tuple = ('OK', _kdf)
            except:
                _msg = traceback.format_exc(2)
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg,False)}")                

        return(_response_tuple)
        
    ## VERIFY the password with its derived key (your hash)
    def kdf_verify_password(self, p_password2verify_1, p_password2verify_2):
    
        # Prepare
        _inputs = f"{self.inputs}|{p_password2verify_1}|{p_password2verify_2}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name         
        _response_tuple = None
        _msg = None
        _password2verify_1_byte = None
        _password2verify_2_b64decode = None
        
        # Transform
        _password2verify_1_byte = self.byte_representation('to_bin', p_password2verify_1)
        _password2verify_2_b64decode = base64.urlsafe_b64decode(p_password2verify_2)
         
        # Create KDF
        _kdf = self.__kdf_create()
        
        # Instance Fernet Obj
        if _kdf[0] == 'OK':
            try:
                _kdf[1].verify( _password2verify_1_byte, _password2verify_2_b64decode)
                _response_tuple = ('OK', True)
            except InvalidKey as _msg:
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            except Exception:
                _msg = traceback.format_exc(2)
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
        else:
            _msg = _kdf[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg)}")            
        
        return(_response_tuple)

    ## Derived Key from the given PASSWORD and SALT - like HASHING password
    def kdf_derive_and_b64encode_key(self, p_password2derive):
        
        # Prepare
        _inputs = f"{self.inputs}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name 
        _response_tuple = None
        _msg = None
        _kdf_derive = None
        _input_value_byte = None
        _output_value_string = None
        _f_key_b64encode = None

        # Transform
        _input_value_byte = self.byte_representation('to_bin', p_password2derive)
        
        # Create KDF
        _kdf = self.__kdf_create()
        
        # Derive (Hashing)
        if _kdf[0] == 'OK':
            try:
                _kdf_derive = _kdf[1].derive( _input_value_byte )
                _f_key_b64encode =  base64.urlsafe_b64encode(_kdf_derive)
                _output_value_string = self.byte_representation('from_bin', _f_key_b64encode)
                _response_tuple = ('OK', _output_value_string)
            except:
                _msg = traceback.format_exc(2)
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg,False)}")                
        else:
            _msg = _kdf[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg,False)}")           

        return(_response_tuple)

    ## Create Fernet Obj from derived key
    def __kdf_create_fernet_obj(self, p_password2derive):
        
        # Prepare
        _inputs = f"{self.inputs}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name 
        _response_tuple = None
        _msg = None
        _fernet_obj = None

        # Derive Key 
        _f_key = self.kdf_derive_and_b64encode_key(p_password2derive)
       
        # Instance Fernet Obj
        if _f_key[0] == 'OK':
            try:
                _fernet_obj = Fernet( _f_key[1] )
                _response_tuple = ('OK',_fernet_obj)              
            except:
                _msg = traceback.format_exc(2)
                _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg,False)}")                
        else:
            _msg = _f_key[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg)}")             
            
        return(_response_tuple)

    ## ENCRYPT symmetric of p_secret2encrypt (with fernet obj)
    def kdf_encrypt(self, p_password4crypt, p_secret2encrypt):
        
        # Prepare
        _inputs = f"{self.inputs}|{p_secret2encrypt}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name         
        _response_tuple = None
        _msg = None
        _fernet_obj = None
        _input_value_byte = None
        _input_value_crypted = None
        _output_value_string = None

        # Create Obj
        _fernet_obj = self.__kdf_create_fernet_obj(p_password4crypt)
        
        # Crypt with Fernet Obj
        if _fernet_obj[0] == 'OK':

            if not ( self.is_byte(p_secret2encrypt)  ):
                try:
                    _input_value_byte = self.byte_representation('to_bin', p_secret2encrypt)
                    _input_value_crypted = _fernet_obj[1].encrypt(_input_value_byte)
                    _output_value_string = self.byte_representation('from_bin', _input_value_crypted)
                    _response_tuple = ('OK',_output_value_string)
                except:
                    _msg = traceback.format_exc(2)
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")                    
            else:
                try:
                    _input_value_crypted = _fernet_obj[1].encrypt( p_secret2encrypt )
                    _output_value_string = self.byte_representation('from_bin', _input_value_crypted)
                    _response_tuple = ('OK',_output_value_string)
                except:
                    _msg = traceback.format_exc(2)
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
        
        else:
            _msg = _fernet_obj[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg)}")            
        
        return(_response_tuple)

    ## DECRYPT symmetric of p_secret2decrypt (with fernet obj)
    def kdf_decrypt(self, p_password4decrypt, p_secret2decrypt):

        # Prepare
        _inputs = f"{self.inputs}|{p_secret2decrypt}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name         
        _response_tuple = None
        _msg = None
        _fernet_obj = None        
        _input_value_byte = None
        _input_value_decrypted = None
        _output_value_string = None

        # Create Obj
        _fernet_obj = self.__kdf_create_fernet_obj(p_password4decrypt)

        # Decrypt with Fernet Obj
        if _fernet_obj[0] == 'OK':
            
            if not ( self.is_byte(p_secret2decrypt) ):
                try:
                    _input_value_byte = self.byte_representation('to_bin', p_secret2decrypt)
                    _input_value_decrypted = _fernet_obj[1].decrypt(_input_value_byte)
                    _output_value_string = self.byte_representation('from_bin', _input_value_decrypted)
                    _response_tuple = ('OK',_output_value_string)
                except InvalidToken:
                    _msg = 'Wrong password for Kdf Decrypt'
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
                except Exception:
                    _msg = traceback.format_exc(2)
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            else:
                try:
                    _input_value_decrypted = _fernet_obj[1].decrypt(p_secret2decrypt)
                    _output_value_string = self.byte_representation('from_bin', _input_value_decrypted)
                    _response_tuple = ('OK',_output_value_string)
                except InvalidToken:
                    _msg = 'Wrong password for Kdf _decrypt'
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_msg)}")                                                                               
                except Exception:
                    _msg = traceback.format_exc(2)
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")

        else:
            _msg = _fernet_obj[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")

        return(_response_tuple)


    """""""""""""""""""""""""""""""""""""""
    AES256 ( CBC with IV )
    """""""""""""""""""""""""""""""""""""""

    def __aes_padding(self, p_input):
        _block_size = algorithms.AES.block_size / 8            
        _ordinal = _block_size - len(p_input) % _block_size
        _ordinal_int = int(_ordinal)
        _output = p_input + _ordinal_int * chr(_ordinal_int)
        return _output

    def __aes_unpadding(self, p_input):
        _output = p_input[:-ord(p_input[len(p_input) - 1:])]
        return _output

    ## Create Cipher Obj from p_key and with p_iv
    def __aes_create_cipher_obj(self, p_key, p_iv):

        # Prepare
        _inputs = f"{self.inputs}|{p_key}|{p_iv}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name         
        _response_tuple = None
        _msg = None
        _cipher = None

        try:
            _cipher = Cipher(   algorithms.AES(p_key), 
                                modes.CBC(p_iv),
                                backend = self.backend  )
            _response_tuple = ('OK',_cipher)
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
        
        return _response_tuple

    ## AES256 ENCRYPT symmetric of p_secret2encrypt with p_seed
    def aes_encrypt(self, p_seed, p_secret2encrypt):

        # Prepare
        _inputs = f"{self.inputs}|{p_seed}|{p_secret2encrypt}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name
        _response_tuple = None
        _msg = None
        _cipher_response = None
        _cipher = None
        _secret_padded = None
        _secret_byte = None
        _seed_byte = None
        _iv_byte = None
        _iv_hex_byte = None
        _iv_hex_string = None
        _encryptor = None
        _encrypted_byte = None
        
        ## Prepare Secret, Seed
        _secret_padded = self.__aes_padding(p_secret2encrypt)
        _secret_byte = self.byte_representation('to_bin', _secret_padded)
        _seed_byte = self.hex_representation('from_hex', p_seed)
        
        ## Generate IV
        _iv_byte = self.generate_random_binary_data(16)
        _iv_hex_byte = self.hex_representation('to_hex', _iv_byte)
        _iv_hex_string = self.byte_representation('from_bin', _iv_hex_byte)
        
        ## Get Cipher
        _cipher_response = self.__aes_create_cipher_obj(_seed_byte, _iv_byte)
        if _cipher_response[0]=='OK':
            _cipher = _cipher_response[1]
        else:
            _msg = _cipher_response[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")

        ## Encrypt
        try:
            _encryptor = _cipher.encryptor()
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple
        try:
            _encrypted_byte = _encryptor.update(_secret_byte) + _encryptor.finalize()
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple

        ## Return
        _response_tuple = ('OK',_encrypted_byte, _iv_hex_string)
        
        return _response_tuple

    ## AES256 DECRYPT symmetric of p_secret2decrypt with p_seed and p_iv
    def aes_decrypt(self, p_seed, p_iv, p_secret2decrypt):
        
        # Prepare
        _inputs = f"{self.inputs}|{p_seed}|{p_iv}|{p_secret2decrypt}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name
        _response_tuple = None
        _msg = None
        
        _seed_byte = None
        _iv_byte = None
        _cipher = None
        _decryptor = None
        _decrypted_byte = None
        _decrypted_text = None
        _decrypted_text_unpadded = None
        
        ## Prepare Seed
        _seed_byte = self.hex_representation('from_hex', p_seed)

        ## Prepare IV
        _iv_byte = self.hex_representation('from_hex', p_iv)

        ## Get Cipher
        _cipher_response = self.__aes_create_cipher_obj(_seed_byte, _iv_byte)
        if _cipher_response[0]=='OK':
            _cipher = _cipher_response[1]
        else:
            _msg = _cipher_response[1]
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")

        ## Decrypt
        try:
            _decryptor = _cipher.decryptor()
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple
        try:
            _decrypted_byte = _decryptor.update(p_secret2decrypt) + _decryptor.finalize()
            _decrypted_text = self.byte_representation('from_bin', _decrypted_byte)
            _decrypted_text_unpadded = self.__aes_unpadding(_decrypted_text)
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple

        ## Return
        _response_tuple = ('OK', _decrypted_text_unpadded)
        
        return _response_tuple


    """""""""""""""""""""""""""""""""""""""
    SHA256
    """""""""""""""""""""""""""""""""""""""
    
    def make_sha256(self, p_secret2hash):

        # Prepare
        _inputs = f"{self.inputs}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name
        _response_tuple = None
        _msg = None
        _secret_byte = None
        _digest = None
        _secret_hashed_byte = None
        _secret_hashed_hex_byte = None
        _secret_hashed_hex_string = None
        
        ## Prepare Secret
        _secret_byte = self.byte_representation('to_bin', p_secret2hash)
        
        ## HASH
        try:
            _digest = hashes.Hash(  hashes.SHA256(),
                                    backend=self.backend    )
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple
        try:
            _digest.update(_secret_byte)
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple
        try:
            _secret_hashed_byte = _digest.finalize()
            _secret_hashed_hex_byte = self.hex_representation('to_hex', _secret_hashed_byte)
            _secret_hashed_hex_string = self.byte_representation('from_bin', _secret_hashed_hex_byte)
        except Exception:
            _msg = traceback.format_exc(2)
            _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")
            return _response_tuple

        ## Return
        _response_tuple = ('OK', _secret_hashed_hex_string)
        
        return _response_tuple

    """""""""""""""""""""""""""""""""""""""
    CHECKSUM file ( SHA256 or BLAKE2b )
    """""""""""""""""""""""""""""""""""""""
    
    def checksum_file(self, p_algo2checksum, p_file_path, p_file_name):
        
        # Prepare
        _inputs = f"{self.inputs}|{p_algo2checksum}|{p_file_path}|{p_file_name}"
        _module_name = __name__
        _func_name = inspect.currentframe().f_code.co_name         
        _response_tuple = None
        _msg = None
        _file = f"{p_file_path}{p_file_name}"
        _algo_checksum_file = None
        _checksum = None
        _checksum_b64encode = None
        _output_value_string = None
        
        # Choose Algorithm
        if p_algo2checksum.lower() == 'sha256':
            _algo_checksum_file = hashes.SHA256()
        elif p_algo2checksum.lower() == 'blake2':
            _algo_checksum_file = hashes.BLAKE2b(64)
        else:
            _msg = 'Unknown algorithm'
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg)}")            
            return(_response_tuple)
            
        if os.path.exists(_file):
        
            with open(_file, "rb") as f:
                try:
                    _file_hash = hashes.Hash(   _algo_checksum_file, 
                                                backend=self.backend    )
                    while chunk := f.read(8192): # Read the binary file to the end (8192)
                        _file_hash.update(chunk)
                except Exception:
                    _response_tuple = ('NOK', f"{ utility.my_log('Exception',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs,_msg)}")                    

            _checksum = _file_hash.finalize()
            _checksum_b64encode = base64.urlsafe_b64encode(_checksum )
            _output_value_string = self.byte_representation('from_bin', _checksum_b64encode)
            _response_tuple = ('OK',_output_value_string)
            
        else:
            _msg = 'File does not exist'
            _response_tuple = ('NOK', f"{ utility.my_log('Error',_module_name,_func_name,inspect.currentframe().f_lineno,_inputs, _msg)}")            
            
        return(_response_tuple)
