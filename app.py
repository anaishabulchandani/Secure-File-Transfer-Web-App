import streamlit as st
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct
from io import BytesIO

# constants
MAGIC = b'SFT1'  # 4 bytes
SALT_SIZE = 16
IV_SIZE = 16
KDF_ITERATIONS = 200_000
KEY_SIZE = 32  # AES-256

backend = default_backend()


def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=backend,
    )
    return kdf.derive(password_bytes)


def encrypt_bytes(file_bytes: bytes, filename: str, password: str) -> bytes:
    # generate salt and iv
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    # pad
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # build header: MAGIC (4) | filename_len (2) | filename | salt (16) | iv (16) | ciphertext
    filename_bytes = filename.encode('utf-8')
    if len(filename_bytes) > 65535:
        raise ValueError('Filename too long')
    header = bytearray()
    header += MAGIC
    header += struct.pack('>H', len(filename_bytes))
    header += filename_bytes
    header += salt
    header += iv
    return bytes(header) + ciphertext


def decrypt_bytes(encrypted_bytes: bytes, password: str) -> (bytes, str):
    # parse header
    if len(encrypted_bytes) < 4 + 2 + SALT_SIZE + IV_SIZE:
        raise ValueError('File too small or corrupt')
    p = 0
    magic = encrypted_bytes[p:p+4]
    p += 4
    if magic != MAGIC:
        raise ValueError('Not a valid SFT1 encrypted file')
    filename_len = struct.unpack('>H', encrypted_bytes[p:p+2])[0]
    p += 2
    filename_bytes = encrypted_bytes[p:p+filename_len]
    p += filename_len
    filename = filename_bytes.decode('utf-8')
    salt = encrypted_bytes[p:p+SALT_SIZE]
    p += SALT_SIZE
    iv = encrypted_bytes[p:p+IV_SIZE]
    p += IV_SIZE
    ciphertext = encrypted_bytes[p:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()

    return plain, filename


# --- Streamlit UI
st.set_page_config(page_title='Secure File Transfer ', layout='centered')
st.title(' Secure File Transfer — Streamlit (AES with Password)')
st.write('Encrypt files with a password, download the encrypted blob, and decrypt using the same password.')

mode = st.radio('Choose action:', ('Encrypt a file', 'Decrypt a file'))

if mode == 'Encrypt a file':
    uploaded_file = st.file_uploader('Upload file to encrypt', accept_multiple_files=False)
    password = st.text_input('Enter password (used to derive AES key)', type='password')
    confirm = st.checkbox('Show advanced options')
    if confirm:
        st.info(f'Using PBKDF2-HMAC-SHA256 with {KDF_ITERATIONS} iterations, salt length {SALT_SIZE} bytes.')

    if uploaded_file and password:
        raw = uploaded_file.read()
        try:
            encrypted_blob = encrypt_bytes(raw, uploaded_file.name, password)
        except Exception as e:
            st.error(f'Encryption failed: {e}')
        else:
            enc_filename = uploaded_file.name + '.sft'
            st.success('File encrypted successfully!')
            st.download_button('Download encrypted file', data=encrypted_blob, file_name=enc_filename)
            st.write('Share the encrypted file with the recipient. They will need the same password to decrypt it.')
            st.markdown('**Notes:** The encrypted file already contains metadata (original filename). Do not change the file extension.')
    elif uploaded_file and not password:
        st.warning('Enter a password to proceed.')

else:  # Decrypt
    enc_file = st.file_uploader('Upload encrypted file (.sft)', accept_multiple_files=False)
    password = st.text_input('Enter password to decrypt', type='password', key='dec_pw')
    if enc_file and password:
        encrypted_bytes = enc_file.read()
        try:
            plain, orig_filename = decrypt_bytes(encrypted_bytes, password)
        except Exception as e:
            st.error(f'Decryption failed: {e}')
        else:
            st.success('Decryption succeeded!')
            # Provide download button with original filename
            st.download_button('Download decrypted file', data=plain, file_name=orig_filename)
            st.write('If the download fails, try copying the bytes to a file manually (advanced).')
    elif enc_file and not password:
        st.warning('Enter password to decrypt the uploaded file.')

# Footer
st.markdown('---')
st.caption('Educational demo: AES-256 (CBC) with PBKDF2 key derivation. Not audited for production use.')

