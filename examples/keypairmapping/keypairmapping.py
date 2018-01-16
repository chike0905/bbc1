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
import sys
import sqlite3

sys.path.append("../../")
from bbc1.common import bbclib
from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *

# For test
import os

from IPython import embed
from IPython.terminal.embed import InteractiveShellEmbed

ASSET_GROUP_ID = bbclib.get_new_id("keychain", include_timestamp=False)
DOMAIN_ID = bbclib.get_new_id("keychain", include_timestamp=False)

dbpath = "identifier.sqlite"
con = sqlite3.connect(dbpath)
cur = con.execute("SELECT * FROM sqlite_master WHERE type='table' and name='identifier'")
if cur.fetchone() == None:
    print("Create identifier table")
    con.execute("CREATE TABLE 'identifier' (id INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT, txid TEXT,   created_at TIMESTAMP DEFAULT (DATETIME('now','localtime')))")
    con.commit()

def create_keypair(keyname):
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(keyname, "wb") as fout:
        fout.write(keypair.private_key)
    with open(keyname+".pub", "wb") as fout:
        fout.write(keypair.public_key)
    return keypair

def create_keymap(user_id, sig_keypair, pubkeys):
    res = create_keymap_tx(user_id, user_id, sig_keypair, pubkeys, ref_tx = None)
    if res:
        sql = u"insert into identifier(identifier, txid) values (?, ?)"
        con.execute(sql, (binascii.hexlify(user_id), binascii.hexlify(res)))
        con.commit()
        return True
    else:
        return False

def create_keymap_tx(user_id, approver_id, sig_keypair, pubkeys, ref_tx = None):
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=ASSET_GROUP_ID, event_num=len(pubkeys))
    for a in range(len(pubkeys)):
        transaction.events[a].add(mandatory_approver=approver_id, asset_group_id=ASSET_GROUP_ID)
        transaction.events[a].asset.add(user_id=user_id, asset_body=pubkeys[a])

    if ref_tx:
        #TODO it can verify any key in ref transaction
        #if binascii.hexlify(sig_keypair.public_key) == binascii.hexlify(ref_tx.signatures[0].pubkey):
        reference = bbclib.add_reference_to_transaction(ASSET_GROUP_ID, transaction, ref_tx, 0)
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                private_key=sig_keypair.private_key,
                                public_key=sig_keypair.public_key)
        transaction.references[0].add_signature(user_id=user_id, signature=sig)
        #else:
        #    return False
    else:
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                private_key=sig_keypair.private_key,
                                public_key=sig_keypair.public_key)
        transaction.get_sig_index(user_id=user_id)
        transaction.add_signature(user_id=user_id, signature=sig)

    txid = insert_tx_bbc_core(transaction, user_id)
    return txid

def add_key_to_keymap(user_id, sig_key, addpubkey):
    id, ref_txid = get_keymap_txid_from_identifier(user_id)
    assert ref_txid
    ref_tx = get_tx_from_txid(ref_txid, user_id)
    assert ref_tx

    old_keys = []
    for old_key_event in ref_tx.events:
        old_key = old_key_event.asset.asset_body
        old_keys.append(old_key)
    old_keys.append(addpubkey)
    res = create_keymap_tx(user_id, user_id, sig_key, old_keys, ref_tx)
    assert res
    if res:
        sql = u"update identifier set txid = (?) where id = (?);"
        con.execute(sql, (binascii.hexlify(res), id))
        con.commit()
        return True
    else:
        return False

def rm_key_from_keymap(user_id,  sig_key, rmpubkey):
    id, ref_txid = get_keymap_txid_from_identifier(user_id)
    assert ref_txid
    ref_tx = get_tx_from_txid(ref_txid, user_id)
    assert ref_tx

    old_keys = []
    for old_key_event in ref_tx.events:
        old_key = old_key_event.asset.asset_body
        old_keys.append(old_key)

    old_keys.remove(rmpubkey)
    res = create_keymap_tx(user_id, user_id, sig_key, old_keys, ref_tx)
    if res:
        sql = u"update identifier set txid = (?) where id = (?);"
        con.execute(sql, (binascii.hexlify(res), id))
        con.commit()
        return True
    else:
        return False

def get_keymap_txid_from_identifier(user_id):
    sql = "select id, txid from identifier where identifier = (?)"
    cur.execute(sql,(binascii.hexlify(user_id), ))
    result = cur.fetchall()
    if len(result) == 0:
        return False
    else:
        keymap_txid = binascii.unhexlify(result[0][1])
        return result[0][0], keymap_txid


def verify_sig_by_keymap(txid, user_id):
    tx = get_tx_from_txid(txid, user_id)
    assert tx
    digest = tx.digest()

    id, keymap_txid = get_keymap_txid_from_identifier(user_id)
    assert keymap_txid

    keymaptx = get_tx_from_txid(keymap_txid, user_id)
    assert keymaptx

    pubkeys = []
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
    txid = insert_tx_bbc_core(transaction, user_id)
    return txid


def asset_group_setup():
    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, loglevel="all")
    tmpclient.domain_setup(DOMAIN_ID, "simple_cluster")
    tmpclient.callback.synchronize()
    tmpclient.register_asset_group(domain_id=DOMAIN_ID, asset_group_id=ASSET_GROUP_ID)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    print("Domain %s and asset_group %s are created." % (binascii.b2a_hex(DOMAIN_ID[:4]).decode(),
                                                        binascii.b2a_hex(ASSET_GROUP_ID[:4]).decode()))
    print("Setup is done.")

def setup_bbc_app_client(user_id):
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_asset_group_id(ASSET_GROUP_ID)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client

def insert_tx_bbc_core(transaction, user_id):
    print("insert tx to bbc core")
    bbc_app_client = setup_bbc_app_client(user_id)

    ret = bbc_app_client.insert_transaction(ASSET_GROUP_ID, transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        return False
    return  response_data[KeyType.transaction_id]

def get_tx_from_txid(txid, user_id):
    bbc_app_client = setup_bbc_app_client(user_id)
    bbc_app_client.search_transaction(ASSET_GROUP_ID, txid)
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        return False
    return bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])

# TODO

def test():
    asset_group_setup()

    KEYNUM = 4
    keys = []
    for a in range(KEYNUM):
        keys.append(create_keypair(str(a)))

    approver_id = bbclib.get_new_id("keychain_user", include_timestamp=False)
    user_id = bbclib.get_new_id("keychain_user", include_timestamp=False)


    print("Create testTX")
    testtxs = []
    for a in range(KEYNUM):
        testtxs.append(make_empty_tx(user_id, approver_id, keys[a]))

    print("=================================================")
    print("Create Key Mapping TX")
    pubkeys = []
    for a in range(KEYNUM):
        pubkeys.append(binascii.b2a_hex(keys[a].public_key))
    keymaptx = create_keymap(user_id, keys[0], pubkeys)
    for a in range(KEYNUM):
        print("Verify tx signed by key %s by keymapping" % str(a))
        assert verify_sig_by_keymap(testtxs[a], user_id)
        print("Pass")

    print("=================================================")
    print("verify sig by key not in Key Mapping")
    addkey = create_keypair(str(KEYNUM))
    KEYNUM = KEYNUM + 1
    testtx = make_empty_tx(user_id, approver_id, addkey)
    assert not verify_sig_by_keymap(testtx, user_id)
    print("Not Pass")

    print("=================================================")
    print("add key to Key Mapping")
    addpubkey = binascii.b2a_hex(addkey.public_key)
    keymaptx = add_key_to_keymap(user_id, keys[1], addpubkey)
    for a in range(KEYNUM-1):
        print("Verify tx signed by key %s by keymapping" % str(a))
        assert verify_sig_by_keymap(testtxs[a], user_id)
        print("Pass")

    print("=================================================")
    print("rm key to Key Mapping")
    keymaptx = rm_key_from_keymap(user_id, keys[2], addpubkey)
    for a in range(KEYNUM-1):
        print("Verify tx signed by key %s by keymapping" % str(a))
        assert verify_sig_by_keymap(testtxs[a], user_id)
        print("Pass")


    for a in range(KEYNUM):
        os.remove("./" + str(a))
        os.remove("./" + str(a) + ".pub")

test()
