# s-fre_test
Sıfre test aracı 
Bu aracın kullanıcı dostu bir arayüzü olacak ve kullanıcıların metinlerini girerek şifrelemelerini sağlayacak. Ayrıca, şifrelenmiş metinleri çözmek için de bir seçenek sunulacak.

Python'da bu tür bir uygulama için PyCrypto veya Cryptography gibi kütüphaneler kullanabiliriz. Bu kütüphaneler AES algoritması için gerekli olan fonksiyonları içermektedirfrom Crypto.Cipher import AES
import base64

def encrypt(key, iv, plaintext):
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)
    ciphertext = aes.encrypt(padded_plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(key, iv, ciphertext):
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = aes.decrypt(base64.b64decode(ciphertext)).decode('utf-8')
    return padded_plaintext[:-ord(padded_plaintext[-1])]

key = b'SecretKey1234567'
iv = b'InitializationVe'

plaintext = 'Hello World!'
ciphertext = encrypt(key, iv, plaintext)
print('Ciphertext:', ciphertext)

decrypted_plaintext = decrypt(key, iv, ciphertext)
print('Decrypted plaintext:', decrypted_plaintext)
