import ast
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
key = RSA.generate(4096)
#Public key being stored in file
file_1 = open('file_public.pem', 'wb')
file_1.write(key.publickey().exportKey('PEM'))
file_1.close()
#Private key being stored in file
file_1 = open('file_private.pem', 'wb')
file_1.write(key.exportKey('PEM'))
file_1.close()
#Encryption
file_1 = open('file_public.pem', 'rb')
one_to_read = RSA.importKey(file_1.read())
input_from_user = input("Give message to Encrypt: ")
commmand_to_encrypt = PKCS1_OAEP.new(one_to_read)
output_encryption = commmand_to_encrypt.encrypt(bytes(input_from_user, 'utf-8'))
print("Generated Encrypted message is", output_encryption)
#Decryption
file_2 = open('file_private.pem', 'rb')
two_to_read = RSA.importKey(file_2.read())
input_from_user = input("Give message to Decrypt: ")
command_to_decrypt = PKCS1_OAEP.new(two_to_read)
output_decryption = command_to_decrypt.decrypt(ast.literal_eval(str(input_from_user)))
print("Generated decrypted message is", output_decryption)
