from vault.hvault import seal_vault, vault_init, unseal_vault
from constants.vault_constants import KEY_FILE_PATH, TOKEN_FILE_PATH, VAULT_ADDRESS, SEAL_FILE_PATH

if __name__ == "__main__":
    # init the vault for the first time.
    # the token and seals will be sealed, default is not to show.
    # no thresholds and shares are specified the default will be applied.
    vault_init(url=VAULT_ADDRESS, show_token_keys=True)

    # unseal the vault
    response = unseal_vault(url=VAULT_ADDRESS)
    # check the response
    print(response)

    # seal the vault
    seal_response = seal_vault(url=VAULT_ADDRESS)
    # check the response
    print(seal_response)