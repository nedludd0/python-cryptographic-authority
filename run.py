from my_class import PyCaClass

"""""""""""""""""""""""""""""""""""""""""""""
Cryptography
"""""""""""""""""""""""""""""""""""""""""""""


def main(choose):
    
    """""""""
    Prepare
    """""""""
    kdf_salt = f"15511234"
    kdf_secret = '55555555555555555555555555555ddddddddddddDDDD5555555555555555555'
    
    aes_secret_1 = 'VzcO2m1u8tf2h9eKIFCdF5kp01wskUIcPXDgap60rhshbgnjnOZukDYWCCGpb1ht'
    aes_secret_2 = 'powq9NpTe9kwcxJVbC0gUrt6drciX8NZezeBNXSz35DGpkYoZaMxro6lhJWL5ET0'
    #aes_secret_1 = 'PLUTO'
    #aes_secret_2 = 'PIPPO'
    aes_secret = f"{aes_secret_1}~~{aes_secret_2}"
    aes_seed = '62c42ea75723f99d11bf110fefa58eb3deab3e9002daf1f0a662e95051eee757'

    sha256_secret = 'RRAOGRMIYVIWBQTZUILDAASAYDTAQHUZTS9XZVNMBAQAZGPDURAOUXP9UUSUO9KCYDBLONBJZHOKBUYUU'

    # KDF - Crypt & Decrypt with input password
    if choose == 1:
        
        """""""""""""""""""""""""""
        Crypt & Decrypt
        """""""""""""""""""""""""""

        # Inputs
        print(f"{chr(10)}------------")
        print(f"-- INPUTs --")
        print(f"------------")
        password4crypt = input("Choose Password to Crypt: ")
        password4decrypt = input("Choose Password to DeCrypt: ")              
        print(f"{chr(10)}")
        
        # CREATE PYCA OBJ
        _pyca_obj = PyCaClass(kdf_salt)

        # KDF ENCRYPT
        _secret_encrypted_response = _pyca_obj.kdf_encrypt( p_password4crypt = password4crypt, 
                                                            p_secret2encrypt = kdf_secret  )
        if _secret_encrypted_response[0] == 'OK':
            _secret_encrypted = _secret_encrypted_response[1]
            print('---------------------------------------------------------')
            print( f"KDF_ENCRYPT" )
            print( f"SECRET_ENCRYPTED: {_secret_encrypted}" )
            print('---------------------------------------------------------')
            print('\n')
        
        else:
            print(_secret_encrypted_response[1])
            exit(1)
        
        # KDF DECRYPT
        _secret_decrypted_response = _pyca_obj.kdf_decrypt( p_password4decrypt = password4decrypt, 
                                                            p_secret2decrypt = _secret_encrypted    )
        if _secret_decrypted_response[0] == 'OK':
            _secret_decrypted = _secret_decrypted_response[1]
            print('---------------------------------------------------------')
            print( f"KDF_DECRYPT" )
            print( f"SECRET_DECRYPTED: {_secret_decrypted}" )
            print('---------------------------------------------------------')
            print('\n')
            
        else:
            print(_secret_decrypted_response[1])
            exit(1)
        
        # KDF CHECK
        if kdf_secret == _secret_decrypted:
            print('---------------------------------------------------------')
            print( f"KDF CHECK OK " )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print('---------------------------------------------------------')
            print( f"KDF CHECK NOK " )
            print('---------------------------------------------------------')
            print('\n')

    # KDF - Verify Password
    elif choose == 2:

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

        # CREATE PYCA OBJ
        _pyca_obj = PyCaClass(kdf_salt)
        
        # DERIVE KEY
        _key_derived = _pyca_obj.kdf_derive_and_b64encode_key( p_password2derive = password2store ) 
        if _key_derived[0] == 'OK':

            # VERIFY
            _check = _pyca_obj.kdf_verify_password( p_password2verify_1 = password2check,
                                                    p_password2verify_2 = _key_derived[1])
            if _check[0] == 'OK':
                print('---------------------------------------------------------')
                print(f"Password Derived: {_key_derived[1]}")
                print( f"Check Password: {_check[1]}" )
                print('---------------------------------------------------------')
                print('\n')
            else:
                print(_check[1])
                exit(1)

        else:
            print(_key_derived[1])
            exit(1)

    # AES256 - Crypt & Decrypt
    elif choose == 3:

        # CREATE PYCA OBJ
        _pyca_obj = PyCaClass()
        
        # AES ENCRYPT
        _secret_encrypted_response = _pyca_obj.aes_encrypt( p_seed = aes_seed,
                                                            p_secret2encrypt = aes_secret   )
        if _secret_encrypted_response[0] == 'OK':
            _secret_encrypted_byte = _secret_encrypted_response[1]
            _iv_hex_string = _secret_encrypted_response[2]
            print('---------------------------------------------------------')
            print( f"AES ENCRYPT" )
            print( f"ENCRYPTED_HEX_STRING: {_pyca_obj.byte_representation('from_bin', _pyca_obj.hex_representation('to_hex', _secret_encrypted_byte) ) }" )
            print( f"IV_HEX_STRING: {_iv_hex_string}" )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print(_secret_encrypted_response[1])
            exit(1)

        # AES DECRYPT
        _secret_decrypted_response = _pyca_obj.aes_decrypt( p_seed = aes_seed, 
                                                            p_iv = _iv_hex_string,
                                                            p_secret2decrypt = _secret_encrypted_byte  )
        if _secret_decrypted_response[0] == 'OK':
            _secret_decrypted_text = _secret_decrypted_response[1]
            print('---------------------------------------------------------')
            print( f"AES DECRYPT" )
            print( f"DECRYPTED_TEXT: {_secret_decrypted_text}" )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print(_secret_decrypted_response[1])
            exit(1)

        # AES CHECK
        if aes_secret == _secret_decrypted_text:
            print('---------------------------------------------------------')
            print( f"AES CHECK OK " )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print('---------------------------------------------------------')
            print( f"AES CHECK NOK " )
            print('---------------------------------------------------------')
            print('\n')

    # SHA256 - To hash a secret
    elif choose == 4:

        # CREATE PYCA OBJ
        _pyca_obj = PyCaClass()
        
        # MAKE SHA256
        _make_sha256_response = _pyca_obj.make_sha256( p_secret2hash = sha256_secret  )
        if _make_sha256_response[0] == 'OK':
            _sha256_hex_string = _make_sha256_response[1]
            print('---------------------------------------------------------')
            print( f"MAKE SHA256" )
            print( f"Sha256 Hex String: {_sha256_hex_string}" )
            print('---------------------------------------------------------')
            print('\n')
        else:
            print(_make_sha256_response[1])

    # SHA256 or BLAKE2 - To CheckSum a File
    elif choose == 5:
        
        _file_path  = './'
        _file1_name = 'Example1.pdf'
        _file2_name = 'Example1_copy.pdf'
        _file3_name = 'Example1_modified.pdf'

        # Inputs
        print(f"{chr(10)}------------")
        print(f"-- INPUTs --")
        print(f"------------")
        _algo2checksum = input("Choose Algorithm to checksum (sha256 [s] or blake2 [b]): ")            
        print(f"{chr(10)}")

        # CREATE PYCA OBJ
        _pyca_obj = PyCaClass()
        
        # Calculate checksum1
        _checksum1  = _pyca_obj.checksum_file(  p_algo2checksum = 'sha256' if _algo2checksum == 's' else 'blake2', 
                                                p_file_path = _file_path, 
                                                p_file_name = _file1_name   )
        if _checksum1[0] == 'NOK':
            print(_checksum1[1])
            exit(1)
        
        # Calculate checksum2
        _checksum2 = _pyca_obj.checksum_file(   p_algo2checksum = 'sha256' if _algo2checksum == 's' else 'blake2',
                                                p_file_path = _file_path, 
                                                p_file_name = _file2_name   )
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
    
    message =   f"{chr(10)}CHOOSE WHAT TO DO: {chr(10)}"\
                f"[1] KDF - Crypt&Decrypt {chr(10)}"\
                f"[2] KDF - Verify Password {chr(10)}"\
                f"[3] AES256 - Crypt&Decrypt {chr(10)}"\
                f"[4] SHA256 - to hash a secret {chr(10)}"\
                f"[5] SHA256 or BLAKE2 - to CheckSum a File {chr(10)}"
    
    choose = input( message ) 
    
    main( int(choose) )
