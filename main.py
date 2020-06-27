# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt

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
        
        
        _fernet_obj         = PyCaClass( salt, password2store )
        
        _password_stored    =  _fernet_obj.derive_and_b64encode_key() 
        
        if _password_stored[0] == 'OK':
        
            _check  = _fernet_obj.verify_password( _password_stored[1], password2check )
        
            if _check[0] == 'OK':
                
                print('---------------------------------------------------------')
                print(f"Password Stored: {_password_stored}")
                print( f"Check Password: {_check[1]}" )
                print('---------------------------------------------------------')
                print('\n')
                
            else:
                print(_check[1])
                exit(1)

        else:
            print(_password_stored[1])
            exit(1)

    # Crypt&Decrypt with password
    elif choose == 2:
        
        """""""""""""""""""""""""""
        Crypt & Decrypt
        """""""""""""""""""""""""""

        # Inputs
        print(f"{chr(10)}------------")        
        print(f"-- INPUTs --")
        print(f"------------")        
        password4crypt_decrypt = input("Choose Password to Use: ")       
        print(f"{chr(10)}")

        
        ### CRYPT WITH FERNET
        
        _fernet_obj     = PyCaClass( salt, password4crypt_decrypt )
                                                
        _key_encrypt    = _fernet_obj.crypt(key)
        
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
        
        _fernet_obj     = PyCaClass( salt, password4crypt_decrypt )
                                                
        _key_decrypt    = _fernet_obj.decrypt(_key_encrypt[1])
        
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


if __name__ == "__main__":

    choose = input(f"{chr(10)}CHOOSE WHAT TO DO (Verify Password 1, Crypt&Decrypt with password 2): ") 
    
    main(int(choose))
