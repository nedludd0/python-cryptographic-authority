# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt
# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/

from my_class import PyCaClass

def main(choose):
    """""""""""""""""""""""""""""""""""""""""""""
    Cryptography
    """""""""""""""""""""""""""""""""""""""""""""

    """""""""
    Prepare
    """""""""
    salt    = f"15511234"
    key     = '55555555555555555555555555555ddddddddddddDDDD5555555555555555555'

    # Verify Password
    if choose == 1:

        """""""""""""""""""""""""""
        Hash & Verify Password
        """""""""""""""""""""""""""

        # Inputs
        print(f"{chr(10)}------------")        
        print(f"-- INPUTs --")
        print(f"------------")        
        password2store = input("Choose Password to Store: ") 
        password2check = input("Choose Password to Check: ")       
        print(f"{chr(10)}")
        
        
        _fernet_obj         = PyCaClass( salt )
        
        _password_hashed    =  _fernet_obj.derive_and_b64encode_key( password2store ) 
        
        if _password_hashed[0] == 'OK':
        
            _check  = _fernet_obj.verify_password( _password_hashed[1], password2check )
        
            if _check[0] == 'OK':
                
                print('---------------------------------------------------------')
                print(f"Password Stored: {_password_hashed[1]}")
                print( f"Check Password: {_check[1]}" )
                print('---------------------------------------------------------')
                print('\n')
                
            else:
                print(_check[1])
                exit(1)

        else:
            print(_password_hashed[1])
            exit(1)

    # Crypt & Decrypt with input password
    elif choose == 2:
        
        """""""""""""""""""""""""""
        Crypt & Decrypt
        """""""""""""""""""""""""""

        # Inputs
        print(f"{chr(10)}------------")        
        print(f"-- INPUTs --")
        print(f"------------")        
        password4crypt      = input("Choose Password to Crypt: ")
        password4decrypt    = input("Choose Password to DeCrypt: ")              
        print(f"{chr(10)}")

        
        ### CRYPT WITH FERNET
        
        _fernet_obj     = PyCaClass( salt )
                                                
        _key_encrypt    = _fernet_obj.crypt( password4crypt , key )
        
        if _key_encrypt[0] == 'OK':
            
            print('---------------------------------------------------------')
            print( f"Encrypt response: {_key_encrypt[0]}" )
            print( _key_encrypt[1] )
            print('---------------------------------------------------------')
            print('\n')
        
        else:
            print(_key_encrypt[1])
            exit(1)
        
        ### DECRYPT WITH FERNET
        
        _fernet_obj     = PyCaClass( salt )
                                                
        _key_decrypt    = _fernet_obj.decrypt( password4decrypt , _key_encrypt[1])
        
        if _key_decrypt[0] == 'OK':
            
            print('---------------------------------------------------------')
            print( f"DeCrypt response: {_key_decrypt[0]}" )        
            print( _key_decrypt[1] )
            print('---------------------------------------------------------')
            print('\n')
            
        else:
            print(_key_decrypt[1])
            exit(1)
        
        ### Verify Crypt & DeCrypt
        
        print('---------------------------------------------------------')
        
        print('Verify Crypt & DeCrypt')
        if key == _key_decrypt[1] :
            print('OK')
        else:
            print('NOK')
        
        print('---------------------------------------------------------')

    # CheckSum File SHA256 or BLAKE2
    elif choose == 3:
        
        _file_path  = './'
        _file1_name = 'Example1.pdf'
        _file2_name = 'Example1_copy.pdf'
        _file3_name = 'Example1_modified.pdf'        

        # Inputs
        print(f"{chr(10)}------------")        
        print(f"-- INPUTs --")
        print(f"------------")        
        _algo2checksum = input("Choose Algorithm to checksum (sha256 or blake2): ")            
        print(f"{chr(10)}")

        _fernet_obj = PyCaClass( salt )
        
        # Calculate checksum1
        _checksum1  = _fernet_obj.checksum_file(_algo2checksum, _file_path, _file1_name)
        if _checksum1[0] == 'NOK':
            print(_checksum1[1])
            exit(1)
        
        # Calculate checksum2
        _checksum2 = _fernet_obj.checksum_file(_algo2checksum, _file_path, _file2_name)
        if _checksum2[0] == 'NOK':
            print(_checksum2[1])
            exit(1)
            
        # Verify checksum
        if _checksum1[1] == _checksum2[1]:
            print('---------------------------------------------------------')
            print( f"The files are the same" )        
            print( f"Checksum1: {_checksum1[1]}" )
            print( f"Checksum2: {_checksum2[1]}" )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print('---------------------------------------------------------')
            print( f"The files are not the same" )        
            print( f"Checksum1: {_checksum1[1]}" )
            print( f"Checksum2: {_checksum2[1]}" )
            print('---------------------------------------------------------')
            print('\n')
            
if __name__ == "__main__":

    choose = input(f"{chr(10)}CHOOSE WHAT TO DO (Verify Password 1, Crypt&Decrypt with input password 2, CheckSum File 3): ") 
    
    main(int(choose))
