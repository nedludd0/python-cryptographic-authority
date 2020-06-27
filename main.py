# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt

from my_class import PyCaClass

def main():
    """""""""""""""""""""""""""""""""""""""""""""
    Cryptography
    """""""""""""""""""""""""""""""""""""""""""""

    """""""""
    Input
    """""""""
    salt    = f"15511234"
    key     = '55555555555555555555555555555ddddddddddddDDDD5555555555555555555'

    # Inputs
    print(f"{chr(10)}------------")        
    print(f"-- INPUTs --")
    print(f"------------")        
    password2store = input("Choose Password to Store: ") 
    password2check = input("Choose Password to Check: ")       
    print(f"{chr(10)}")

    
    """""""""""""""""""""""""""
    Hash & Verify Password
    """""""""""""""""""""""""""
    
    _fernet_obj = PyCaClass( password2store, salt )
    
    _check      = _fernet_obj.verify_password( password2check )
    
    if _check[0] == 'OK':
        
        print('---------------------------------------------------------')
        print( f"Verify Password" )
        print( _check[1] )
        print('---------------------------------------------------------')
        print('\n')

    else:
        print(_check[1])
        exit(1)
    
    """""""""""""""""""""""""""
    Crypt & Decrypt
    """""""""""""""""""""""""""
    
    ### CRYPT WITH FERNET
    
    _fernet_obj     = PyCaClass( password2store, salt )
                                            
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
    
    _fernet_obj     = PyCaClass( password2store, salt )
                                            
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
    
    """""""""""""""""""""""""""
    Verify Crypt & DeCrypt
    """""""""""""""""""""""""""
    
    print('---------------------------------------------------------')
    
    print('Verify Crypt & DeCrypt')
    if key == _key_decrypt[1] :
        print('OK')
    else:
        print('NOK')
    
    print('---------------------------------------------------------')


if __name__ == "__main__":
    main()
