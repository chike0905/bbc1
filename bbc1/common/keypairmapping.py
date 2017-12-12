# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import binascii

import bbclib

# For debug
import os

from IPython import embed
from IPython.terminal.embed import InteractiveShellEmbed

DEFAULT_CORE_PORT = 9000
ASSET_GROUP_ID = bbclib.get_new_id("keychain", include_timestamp=False)
DOMAIN_ID = bbclib.get_new_id("keychain", include_timestamp=False)

def create_keypair(keyname):
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(keyname, "wb") as fout:
        fout.write(keypair.private_key)
    with open(keyname+".pub", "wb") as fout:
        fout.write(keypair.public_key)
    return keypair

def create_keymap_tx(user_id, approver_id, sig_keypair, pubkeys, ref_tx = None):
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=ASSET_GROUP_ID, event_num=len(pubkeys))
    for a in range(len(pubkeys)):
        transaction.events[a].add(mandatory_approver=approver_id, asset_group_id=ASSET_GROUP_ID)
        transaction.events[a].asset.add(user_id=user_id, asset_body=pubkeys[a])

    if ref_tx:
        if binascii.hexlify(sig_keypair.public_key) == binascii.hexlify(ref_tx.signatures[0].pubkey):
            reference = bbclib.add_reference_to_transaction(ASSET_GROUP_ID, transaction, ref_tx, 0)
            sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                    private_key=sig_keypair.private_key,
                                    public_key=sig_keypair.public_key)
            transaction.references[0].add_signature(user_id=user_id, signature=sig)
        else:
            return False
    else:
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                private_key=sig_keypair.private_key,
                                public_key=sig_keypair.public_key)
        transaction.get_sig_index(user_id=user_id)
        transaction.add_signature(user_id=user_id, signature=sig)

    insert_tx_bbc_core(transaction)
    return transaction

def add_key_to_keymap(ref_tx, user_id, approver_id, sig_key, addpubkey):
    old_keys = []
    for old_key_event in ref_tx.events:
        old_key = old_key_event.asset.asset_body
        old_keys.append(old_key)
    old_keys.append(addpubkey)
    transaction = create_keymap_tx(user_id, approver_id, sig_key, old_keys, ref_tx)
    insert_tx_bbc_core(transaction)
    return transaction

def rm_key_from_keymap(ref_tx, user_id, approver_id, sig_key, rmpubkey):
    old_keys = []
    for old_key_event in ref_tx.events:
        old_key = old_key_event.asset.asset_body
        old_keys.append(old_key)
    old_keys.remove(rmpubkey)
    transaction = create_keymap_tx(user_id, approver_id, sig_key, old_keys, ref_tx)
    insert_tx_bbc_core(transaction)
    return transaction

def verify_sig_by_keymap(tx, keymaptx):
    pubkeys = []
    digest = tx.digest()
    for pubkey_event in keymaptx.events:
        pubkey = pubkey_event.asset.asset_body
        sig = bbclib.BBcSignature()
        sig.add(signature=tx.signatures[0].signature, pubkey=binascii.unhexlify(pubkey))
        flag = sig.verify(digest)
        if flag == True:
            return True
    return False

def make_empty_tx(user_id, approver_id, sig_keypair):
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=ASSET_GROUP_ID, event_num=1)
    transaction.events[0].add(mandatory_approver=approver_id, asset_group_id=ASSET_GROUP_ID)
    transaction.events[0].asset.add(user_id=user_id, asset_body="test")
    sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                            private_key=sig_keypair.private_key,
                            public_key=sig_keypair.public_key)
    transaction.get_sig_index(user_id=user_id)
    transaction.add_signature(user_id=user_id, signature=sig)
    insert_tx_bbc_core(transaction)
    return transaction

# TODO
def insert_tx_bbc_core(tx):
    #tx.dump()
    print("insert tx to bbc core")


def test():
    KEYNUM = 4
    keys = []
    for a in range(KEYNUM):
        keys.append(create_keypair(str(a)))

    approver_id = bbclib.get_new_id("keychain_user", include_timestamp=False)
    user_id = bbclib.get_new_id("keychain_user", include_timestamp=False)


    print("Create testTX")
    testtx = make_empty_tx(user_id, approver_id, keys[0])

    print("=================================================")
    print("Create Key Mapping TX")
    pubkeys = []
    for a in range(KEYNUM):
        pubkeys.append(binascii.b2a_hex(keys[a].public_key))
    keymaptx = create_keymap_tx(user_id, approver_id, keys[0], pubkeys)
    assert verify_sig_by_keymap(testtx, keymaptx)

    print("=================================================")
    print("add key to Key Mapping")
    addkey = create_keypair(str(KEYNUM))
    KEYNUM = KEYNUM + 1
    addpubkey = binascii.b2a_hex(addkey.public_key)
    keymaptx = add_key_to_keymap(keymaptx, user_id, approver_id, keys[0], addpubkey)
    assert verify_sig_by_keymap(testtx, keymaptx)

    print("=================================================")
    print("rm key to Key Mapping")
    keymaptx = rm_key_from_keymap(keymaptx, user_id, approver_id, keys[0], addpubkey)
    assert verify_sig_by_keymap(testtx, keymaptx)

    print("=================================================")
    print("verify sig by key not in Key Mapping")
    testtx = make_empty_tx(user_id, approver_id, addkey)
    assert not verify_sig_by_keymap(testtx, keymaptx)

    for a in range(KEYNUM):
        os.remove("./" + str(a))
        os.remove("./" + str(a) + ".pub")

test()
