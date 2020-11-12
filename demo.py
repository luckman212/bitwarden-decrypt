#!/usr/bin/env python3

from getpass import getpass
from tabulate import tabulate

from bitwarden.util import load_user_data
from bitwarden.user_key import UserKey
from bitwarden.crypto_engine import CryptoEngine

user_data = load_user_data()

# gather data
email = user_data['userEmail'].encode('utf-8')
kdf = user_data['kdf']
kdf_iterations = user_data['kdfIterations']
master_password = getpass().encode('utf-8')

# grab a secret
ciphers_key = 'ciphers_%s' % ( user_data['userId'] )
ciphers = iter(user_data[ciphers_key].values())
this_cipher = next(ciphers)

n_enc = this_cipher['name']
un_enc = this_cipher['login']['username']
pw_enc = this_cipher['login']['password']
et = n_enc[0]

# produce the encryption key
uk = UserKey(email, master_password, kdf, kdf_iterations)
encryption_key = uk.user_key

# decrypt the secret
ce = CryptoEngine(encryption_key, user_data['encKey'])
n_dec = ce.decrypt(n_enc)
un_dec = ce.decrypt(un_enc)
pw_dec = ce.decrypt(pw_enc)

res = [[ n_dec.decode('utf-8'), un_dec.decode('utf-8'), pw_dec.decode('utf-8'), et ]]
table = tabulate(res, headers=['name','username','password','encType'], tablefmt='orgtbl')
print(table)
