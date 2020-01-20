from pyvault.vault.hvault import *


if __name__ == "__main__":
    asa_kw = {
        "username": "admin",
        "password": "P@ssw0rd12356",
        "description": "Example username and password test"
    }
    # unseal the vault
    resp = unseal_vault()
    print(resp)
    
    # enable secret engine, default is kv engine.
    # make the path to be "lab"
    # to access the lab, set the mount point to lab.
    resp = enable_kv_engine(path="lab")
    print(resp)
    
    # create username and password and store in hashicorp vault
    resp = insert_username_password(mount_point="lab", path="asa_fw", **asa_kw)
    print(resp)
    
    # get username and password from vault.
    # get username and password from mount point lab and path asa_fw.
    # I treat the path as the device hostname.
    resp = get_username_password(mount_point="lab", path="asa_fw")
    print(resp)
