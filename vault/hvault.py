import os
from hvac import Client
from hvac.exceptions import InvalidRequest, InvalidPath
from cryptography.fernet import Fernet, InvalidToken
import json
import gc
import SecureString
from glob import glob
from pyvault.constants.vault_constants import SEAL_FILE_PATH, KEY_FILE_PATH, TOKEN_FILE_PATH, SEAL_PATH
from json.decoder import JSONDecodeError


# Consolidate all hvac exceptions.
hvac_exceptions = InvalidPath, InvalidRequest


def set_seal_path():
    if not os.path.exists(SEAL_PATH):
        os.makedirs(SEAL_PATH)


def vault_client_with_token(url="https://127.0.0.1:8200", cipher=None, token_path=None):
    with open(token_path, "rb") as t_file:
        encrypted_token = t_file.read()
    plaintext_token = cipher.decrypt(encrypted_token)
    return Client(url, token=plaintext_token, verify=False)


# If vault is not initialized, initialize vault.
# Then save the seals and token to a file with encryption.
# This is required only once.
def vault_init(shares=5, threshold=3, url="https://127.0.0.1:8200", show_token_keys=False):
    set_seal_path()
    vault_client = Client(url, verify=False)
    if not os.path.isfile(KEY_FILE_PATH):
        fernet_key = Fernet.generate_key()
        with open(KEY_FILE_PATH, "wb") as key_file:
            key_file.write(fernet_key)
    with open(KEY_FILE_PATH, "rb") as key_file:
        key_data = key_file.read()
        cipher = Fernet(key_data)
    if not vault_client.sys.is_initialized():
        output = vault_client.sys.initialize(shares, threshold)
        for i, s in enumerate(output['keys']):
            es = cipher.encrypt(s.encode('utf-8'))
            with open(f"{SEAL_FILE_PATH}{i}", "wb") as s_file:
                s_file.write(es)
        cipher_token = cipher.encrypt(output['root_token'].encode('utf-8'))
        with open(TOKEN_FILE_PATH, "wb") as t_file:
            t_file.write(cipher_token)
        if show_token_keys:
            print(output)

        # cleaning up secrets.
        # convert dict to string with json.dumps, convert to byte with encode.
        SecureString.clearmem(json.dumps(output).encode('utf-8'))
        # remove the sensitive object from memory
        del output
        # only free memory for other use, residuals may still be in memory.
        # secrets may still be in memory if this memory space is not used.
        gc.collect()


# unseal the vault
def unseal_vault(url="https://127.0.0.1:8200"):
    # empty list for collecting the decrypted seals.
    seals = []
    # Collects the seal file paths in a list.
    seal_files = [f for f in glob(f"{SEAL_FILE_PATH}*")]
    # get the key to encrypt
    with open(KEY_FILE_PATH, "rb") as unlock:
        cipher_key = unlock.read()
    cipher = Fernet(cipher_key)
    # this vault client includes a token.
    vault_client = vault_client_with_token(url, cipher=cipher, token_path=TOKEN_FILE_PATH)
    # each seal is saved to a file, each file is decrypted based on the seal file list.
    for seal_file in seal_files:
        with open(seal_file, "rb") as s_file:
            encrypted_seal = s_file.read()
            try:
                seal_text = cipher.decrypt(encrypted_seal)
                seals.append(seal_text.decode('utf-8'))
            except InvalidToken:
                # there is an invalid token for some reason, this is a workaround.
                pass
        # collects the seal in a list, decrypted object is a byte hence decode is used.
    # send seals until vault is unsealed.
    while vault_client.sys.is_sealed():
        vault_client.sys.submit_unseal_keys(seals)

    # Remove references and free up memory, use clearmem to remove residuals and contents.
    for seal in seals:
        SecureString.clearmem(seal.encode('utf-8'))
    del seals
    gc.collect()

    return {
        "seal_status": vault_client.seal_status['sealed'],
        "is_authenticated": vault_client.is_authenticated()
    }


# seal the vault, requires the client to include token.
def seal_vault(url="https://127.0.0.1:8200"):
    with open(KEY_FILE_PATH, "rb") as unlock:
        cipher_key = unlock.read()
    cipher = Fernet(cipher_key)
    vault_client = vault_client_with_token(url, cipher=cipher, token_path=TOKEN_FILE_PATH)
    vault_client.sys.seal()
    return {
        "seal_status": vault_client.seal_status['sealed']
    }


# INSERT THE USERNAME AND PASSWORD INTO VAULT
def insert_username_password(url="https://127.0.0.1:8200", mount_point="kv", path=None, **kwargs):
    with open(KEY_FILE_PATH, "rb") as unlock:
        cipher_key = unlock.read()
    cipher = Fernet(cipher_key)
    vault = vault_client_with_token(url, cipher=cipher, token_path=TOKEN_FILE_PATH)
    try:
        vault.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=kwargs,
            mount_point=mount_point,
        )
    except JSONDecodeError:
    # I believe this is a bug in hvac on handling the json, but this breaks the entire script.
    # hence I need to ignore it.
    # I am considering using requests module to call api directly instead of using hvac wrapper.
    # using this hvac is to limited to the bug it has and if I develop more with hvac the harder it is
    # to correct the problem.
        pass
    vault.sys.seal()


# Get username and password from vault.
def get_username_password(url="https://127.0.0.1:8200", mount_point="kv", path=None):
    with open(KEY_FILE_PATH, "rb") as unlock:
        cipher_key = unlock.read()
    cipher = Fernet(cipher_key)
    vault = vault_client_with_token(url, cipher=cipher, token_path=TOKEN_FILE_PATH)
    resp = vault.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
    vault.sys.seal()
    return resp['data'].get('data', None)


# Enable new engine, for username and password use kv version2, version 2 is default.
def enable_kv_engine(url="https://127.0.0.1:8200", backend_type="kv", path="kv"):
    '''
    :param url: hashicorp vault address
    :param backend_type: kv, ssh, ldap, github, aws
    :param path: any name you pick, but must be unique
    :return: response dictionary
    '''
    with open(KEY_FILE_PATH, "rb") as unlock:
        cipher_key = unlock.read()
    cipher = Fernet(cipher_key)
    vault = vault_client_with_token(url, cipher=cipher, token_path=TOKEN_FILE_PATH)
    try:
        vault.sys.enable_secrets_engine(backend_type=backend_type, path=path)
        return {
            "message": f"Engine type {backend_type} and path {path} created.",
            "error": 0
        }
    except hvac_exceptions as e:
        return {
            "message": str(e),
            "error": 1
        }
