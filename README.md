# E-vote Consortium Blockchain
## A Digital Signature Approach to Elections
[![Build Status](https://travis-ci.org/ziscky/doom.svg?branch=master)](https://travis-ci.org/ziscky/doom)

The E-Vote blockchain is a consortium network that supports biometric e-voting for any type of election. It is inspired by the bitcoin
network design but has fundamental differences in the P2P model and the consensus algorithm. NB. E-voting not to be confused with online voting.

## Design Guidelines
1.Authenticity
2.Confidentiality
3.Non-repudiation


---

## Crypto
All cryptographic functionality is implemented using [Crypto++](https://github.com/ziscky/doom/releases). The network supports
1. Elliptic Curve Integrated Encryption Scheme
2. Elliptic Curve Digital Signature Algorithm

Every node on the network maintains 4 cryptographic keys:
1. The ECIES Private/Public Keypair used for encrypting/decrypting messages
2. The ECDSA Private/Public Keypair for creating and verifying digital signatures

The Curve used is the NIST recommended curve: secp521r1

---

## Network Design

The network backbone is built using [OpenDHT](https://github.com/ziscky/doom/releases) which is animplementation of the Kademlia DHT.
### Node discovery
Each node begins with a list known nodes (i.e the ECIES and ECDSA public keys) and a network bootstrap address. A random challenge is posted on the DHT with the key being the ECDSA public key. This leads to a 4-way handshake that results in the authentication of the individual nodes (proving that the public keys belong to them).

### Node communication
Node A encrypts the message using Node B's ECIES public key and signs the message using its(Node A) ECDSA private key. This ensures that only Node B can read the contents of the message and also verify the true origin by verifying the digital signature using Node A's ECDSA public key.


----

## Blockchain Spec
#### General Block Format
| Field        | Description           |
| ------------- |:-------------:|
| block_header      | Sha256(block) |
| prev_hash      | header of previous block      |
| next_hash | header of next block      |
| merkle_root | root hash of the merkle tree      |
| tx_hashes | array of transaction hashes i.e sha256(transaction)     |
| transactions | array of raw transactions      |
| timestamp | timestamp of block acceptance      |

### Data Format
The primary data storage format is MsgpackV2 and above. Transactions can be shared through JSON but they are converted to Msgpack internally.

### Special Blocks
1. Genesis Block
    This contains 1 transaction that contains the election candidate details.
2. Fork Block
    This block contains transactions that are the block headers of all previous blocks. It signifies a rule change in how transactions are verified.
3. Death Block
    This block contains transactions that are all previous block headers.

### Consensus
Being a consortium blockchain, consensus is achieved by 2/3 majority rule. 2/3 of authenticated nodes not known nodes.

### Block Formation
Verified transactions are stored in a mempool until the BLOCK_TIME elapses after which each node forms the block independently. The merkle root is computed from the transactions along with the block header. The nodes then send each other the blocks for verification. Verification involves computing the merkle root and block header and comparing with the received hashes. Each node maintains a vote count for each block and after 2/3 majority is achieved, adds it to the chain.

---

## Voting Application
### Voter Registration
The genesis block contains a transaction with information about election candidates. This serves as a single source of truth for the various voting applications.
A voter registration application captures voter details and derives a deterministic public/private keypair from the biometric information and uses the public key to encrypt the sensitive details. Images are base64 encoded to facilitate easier storage on the blockchain. The voter details are transmitted as a transaction and are signed using the private key. The transaction is also signed and encrypted by the voting applications keypair.
Nodes verify transactions by checking the validity of the digital signatures and checking that the supplied public key cannot verify any other signature (ensuring a voter can't register twice).

### Voting Process
The Election supervisors initiate the forking process, this leads to the nodes generating a fork block and after consensus it is added to the chain. Voters candidate selections are transmitted along with their derived public key and the signature of the selections. Voter information is not stored along with the votes to provide voter confidentiality.
Nodes follow the following process to verify the voting transactions:
1. Verify the digital signature using the provided derived public key
2. Check in the parent chain for a signature that can be verified using the supplied public key (i.e the person is a registered voter)
3. Check in the current chain that the public key cannot verify any other signature (i.e can't vote twice)


### Getting Started
```

Works by reading the /proc pseudo fs so you may need to run the cmds as root
Also make sure the package: procps-ng is installed.(provides ps|pgrep etc)

Help: doom
Rank all PIDs by best OOM score:  doom best
Rank all PIDs by worst OOM score:  doom worst
PID with worst OOM score:  doom next
Top 10 worst OOM scores:  doom worst 10
Top 10 best OOM scores:  doom best 10
Inspect a particular process by name(in this case chrome):  doom inspect chrome
Inspect a particular process by PID:  doom inspect 23456
Show your system's relevant OOM behaviour:  doom policy
```


### Building From Source
Dependencies:
1. OpenDHT
2. Msgpack
3. Crypto++
4. Boost.Python (if you need the python bindings)
```
Easier to build using Cmake.
git clone https:://github.com/ziscky/e-vote
cd evote
mkdir build && cd build
cmake -DPYTHON_EXTENSIONS=ON ..
cd ..
cmake --build ./build --target all -- -j4
cmake --build ./build --target install -- -j4
./evote /path/to/conf.json /path/to/identity.json /path/to/nodes.json
[Mainnet]>>start
```
Running with docker frees you from installing the dependencies.
NB. You have to use host networking to run the container.
```
cd Docker
docker build -t evote/latest .
docker run -i -p 4333:4333 -v /local/path/to/config:/config --net host evote/latest
[Mainnet]>>start
```

### Contiributing
I'm very open to PRs.

 - Fork
 - Create Branch
 - Do magic
 - Initiate PR

