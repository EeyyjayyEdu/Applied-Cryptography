def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""
    
    if plaintext == key:
        print("Plaintext should not be equal to the key")
        return None
        
    if len(plaintext) < len(key):
        print("Plaintext length should be equal or greater than the length of key")
        return None
    
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        xor_result = plaintext_byte ^ key_byte
        ciphertext.append(xor_result)
        
        print(f"Plaintext byte: {bin(plaintext_byte)[2:]:>08} = {chr(plaintext_byte)}")
        print(f"Key byte:       {bin(key_byte)[2:]:>08} = {chr(key_byte)}")
        print(f"XOR result:     {bin(xor_result)[2:]:>08} = {chr(xor_result)}")
        print("--------------------")
        
    print(f"Ciphertext: {''.join([chr(byte_value) for byte_value in ciphertext])}")
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    if len(ciphertext) < len(key):
        print("Ciphertext length should be equal or greater than the length of the key")
        return None
    
    decrypttext = bytearray()
    for i in range(len(ciphertext)):
        ciphertext_byte = ciphertext[i]
        key_byte = key[i % len(key)]
        xor_result = ciphertext_byte ^ key_byte
        decrypttext.append(xor_result)
        
        print(f"Plaintext byte: {bin(ciphertext_byte)[2:]:>08} = {chr(ciphertext_byte)}")
        print(f"Key byte:        {bin(key_byte)[2:]:>08} = {chr(key_byte)}")
        print(f"XOR result:      {bin(xor_result)[2:]:>08} = {chr(xor_result)}")
        print("--------------------")
        
    print(f"Decrypted: {''.join([chr(byte_value) for byte_value in decrypttext])}")
    
    

# Example usage:
plaintext = bytes(input().encode())
key = bytes(input().encode())

ciphertext = xor_encrypt(plaintext, key)
if ciphertext is not None:
    xor_decrypt(ciphertext, key)
