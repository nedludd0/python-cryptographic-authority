# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

from my_class import FernetCryptographyClass

def main():
    """""""""""""""""""""""""""""""""""""""""""""
    Cryptography
    """""""""""""""""""""""""""""""""""""""""""""

    """""""""
    Input
    """""""""
    tg_id           = 15511234
    tg_password     = 'p#sswoR1'
    salt            = f"{tg_id}"
    binance_api_key = '55555555555555555555555555555ddddddddddddDDDD5555555555555555555'
    
    
    """""""""""""""""""""""""""
    Crypt & Decrypt
    """""""""""""""""""""""""""
    
    ### CRYPT WITH FERNET
    
    _input1 = binance_api_key
    
    _fernet_obj = FernetCryptographyClass(  tg_password, 
                                            salt )
                                            
    _binance_key_encrypt = _fernet_obj.crypt(_input1)
    
    if _binance_key_encrypt[0] == 'OK':
        
        print('---------------------------------------------------------')
        print( f"Encrypt response: {_binance_key_encrypt[0]}" )
        print( _binance_key_encrypt[1] )
        print('---------------------------------------------------------')
        print('\n')

    else:
        print(_binance_key_encrypt[1])
        exit(1)
    
    ### DECRYPT WITH FERNET
    
    _input1 = _binance_key_encrypt[1]
    
    _fernet_obj = FernetCryptographyClass(  tg_password, 
                                            salt )
                                            
    _binance_key_decrypt = _fernet_obj.decrypt(_input1)
    
    if _binance_key_decrypt[0] == 'OK':
        
        print('---------------------------------------------------------')
        print( f"DeCrypt response: {_binance_key_decrypt[0]}" )        
        print( _binance_key_decrypt[1] )
        print('---------------------------------------------------------')
        print('\n')
        
    else:
        print(_binance_key_decrypt[1])
        exit(1)
    
    """""""""""""""""""""""""""
    Verify Crypt & DeCrypt
    """""""""""""""""""""""""""
    
    print('---------------------------------------------------------')
    
    print('Verify Crypt & DeCrypt')
    if binance_api_key == _binance_key_decrypt[1] :
        print('OK')
    else:
        print('NOK')
    
    print('---------------------------------------------------------')


if __name__ == "__main__":
    main()
