# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

from crypt_my_functions import FernetCryptographyClass

def main():
    """""""""""""""""""""""""""""""""""""""""""""
    Cryptography
    """""""""""""""""""""""""""""""""""""""""""""

    """""""""
    Input
    """""""""
    tg_id           = 15519490
    tg_password     = 'p#sswoR1'
    salt            = '{}'.format(tg_id)
    binance_api_key = '55555555555555555555555555555ddddddddddddDDDD5555555555555555555'
    binance_sec_key = '333333333ddddFFFFFFFFFFFFff000000000222222222222222222222222222'
    
    
    """""""""""""""""""""""""""
    Crypt & Decrypt
    """""""""""""""""""""""""""
    
    ### CRYPT WITH FERNET
    
    _input1 = binance_api_key
    _input2 = binance_sec_key
    
    _fernet_obj = FernetCryptographyClass(	tg_password, 
                                            salt, 
                                            _input1, 
                                            _input2
                                        )
    _binance_key_encrypt = _fernet_obj.crypt()
    
    if _binance_key_encrypt.get('response') == 'OK':
        
        print('---------------------------------------------------------')
        print( 'Encrypt response: {}'.format(_binance_key_encrypt.get('response')) )
        print( _binance_key_encrypt.get('input1_encrypted') )
        print( _binance_key_encrypt.get('input2_encrypted') )
        print('---------------------------------------------------------')
        print('\n')

    else:
        print('Errore di crypt')
        exit(1)
    
    ### DECRYPT WITH FERNET
    
    _input1 = _binance_key_encrypt.get('input1_encrypted')
    _input2 = _binance_key_encrypt.get('input2_encrypted')
    
    _fernet_obj = FernetCryptographyClass(	tg_password, 
                                            salt, 
                                            _input1, 
                                            _input2
                        )
    _binance_key_decrypt = _fernet_obj.decrypt()
    
    if _binance_key_decrypt.get('response') == 'OK':
        
        print('---------------------------------------------------------')
        print( 'Decrypt response: {}'.format(_binance_key_decrypt.get('response')) )
        print( _binance_key_decrypt.get('input1_decrypted') )
        print( _binance_key_decrypt.get('input2_decrypted') )
        print('---------------------------------------------------------')
        print('\n')
        
    else:
        print('Errore di decrypt')
        exit(1)
    
    """""""""""""""""""""""""""
    Verify Crypt & DeCrypt
    """""""""""""""""""""""""""
    
    print('---------------------------------------------------------')
    
    print('Verify Crypt & DeCrypt')
    if binance_api_key == _binance_key_decrypt.get('input1_decrypted') :
        print('binance_api_key OK')
    if binance_sec_key == _binance_key_decrypt.get('input2_decrypted'):
        print('binance_sec_key OK')
    
    print('---------------------------------------------------------')


if __name__ == "__main__":
    main()
