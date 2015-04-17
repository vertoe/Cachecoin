Porting Bitcoin 0.10 to Cachecoin
=================================

Staging tree for Cachecoin-0.10.


MANDATORY:
----------

- Update strings in config, path and pid (~/.cachecoin)
- Update Ports for communication and RPC (port=2225; rpcport=2224)
- Change version numbers, protocol version, wallet version (compatible with CACH network)
- Add cachecoin seednodes
- Update address versions (Public keys, Multisig keys)
- Change genesisblockhash and timestamp
- Review and update checkpoints
- Adjust PoW algorithm (Scrypt-Jane)
- Update PoW subsidity function (Block value)
- Add Proof of stake according to initial definitions
- Define regression test genesis block
- Update wallet layout and branding
- Reset testnet (v4) with new genesis and address version (start with c)
- BIP0032 addresses xpub and xpriv should start with cachsomething
- Change Cachecoin units to CACH
- Fix internal walletminer
- Check rpcminer
