Cachecoin official development tree
===================================

Cachecoin is a hybrid Scrypt-Jane-Proof-of-Work, Proof-of-Stake and
Proof-of-Node. It was originally developed by **kalgecin** and taken over
by **vertoe** due to a lack of time to spend on this project by kal.

*Note*: The user **kalgecin** on bitcointalk was compromized but he is still
active here on github and has write access to this repository.

*Note*: **vertoe** is in no way related or associated with Fibonacci. Jasin Lee
is officially an idiot and can't damage this project.

* Scrypt-Jane-based coin
* No ASIC miners
* Difficulty adjustment every block.
* Difficulty Adjustment algorithm: Logarithmic
* Block Maturity: 520 Confirms
* Transaction Maturity: 6 Confirmations
* Maximum of ~2 Billion coins per transaction.
* RPCPort: 2224
* Network Port: 2225


Proof-of-Work
-------------

* Uses Scrypt-Kal Proof-of-Work chacha20/8 (N,1,1) hashing algorithm.
* N increases over time to increase memory requirements.
* 15 minute Proof-of-Work block targets.
* The Proof-of-Work subsidy decreases as difficulty increases.
* Maximum Proof-of-Work reward is 100 coins.


Proof-of-Stake
--------------

* Active Proof-of-Stake mining.
* Coins per annum 10% maximum.
* Coin age to stake: 7 days.


Proof-of-Node
-------------

* Generating coins while providing a full node service.
* To be released, details soon (tm).


Contact
-------

Try to reach **vertoe** over at **bitcointalk.org**.

Here is the current [ANN] https://bitcointalk.org/index.php?topic=1021193.0

Report issues here: https://github.com/vertoe/cachecoin/issues


Archives
--------

The old compromized [ANN]-Thread by **kalgecin** is this one:
https://bitcointalk.org/index.php?topic=400389.0
