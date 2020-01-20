constants - vault_constants.py contains the constants necessary to create hashicorp vault client.
Change your hashicorp vault ip address and port in this constants.py.

vault - hvault.py has functions to do these:
1. vault_init - Initialize the vault for the first time, writes the seals and token to seperate files, 
and encrypt these files.
A sub directory - seal - is created in your home directory, within this seal subdirectory,
seal files, token file and key file are stored.
If key and tokens have to be revealed on the console, change show_token_keys=True, 
example vault_init(url=VAULT_ADDRESS, show_token_keys=True)

2. unseal_vault - unseal the vault, has some cleanup to ensure secrets stored in memory are removed.

3. seal_vault - seals the vault.

example.py shows the usage of the script, this is part of my learning on how to automate process
with hashicorp vault.

The code was written using hvac 0.9.6, I had several issues using the hvac wrapper, calling the api directly with requests might be a better choice than using hvac, as whichever unexpected exceptions due to bugs will break my script, and the deeper I use hvac in my code the harder it is to maintain it. I would open another branch by using requests module and will stop using hvac.
