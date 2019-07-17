#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP

#define TX_BROADCAST 0
#define BX_BROADCAST 2
#define AUTH_CHALLENGE 3
#define AUTH_SOLUTION 4
#define BX_UPDATE 5

#define SYNC_TX 10
#define SYNC_RX 11
#define BX_VOTE_RQ 12

#define FORK_BROADCAST 13
#define FORK_TX 14
#define FORK_INIT 15

#define CLOSE_BROADCAST 18
#define CLOSE_TX 16

#define INIT_BROADCAST 19
#define INIT_TX 17

#define BLOCK_MAX 3

#define BLOCK_RQ 20
#define BLOCK_RX 21


#include "network/kdht.hpp"
#include "security/identity.hpp"
#include "utils/utils.hpp"
#include "utils/readerwriterqueue.h"
#include "utils/atomicops.h"


#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <iostream>
#include <fstream>

using json = nlohmann::json;

struct Block{
    int height;
    std::string block_header;
    std::string merkle_root;
    std::vector<std::string> tx_hashes;
    std::unordered_map<std::string,std::string> txs;
    std::string prev_block;
    std::string next_block;
    long timestamp;

    //
    std::string iespk;

    void to_json(json& j, const Block& b) {
        j = json{{"height",b.height},{"block_header", b.block_header}, {"merkle_root", b.merkle_root}, {"tx_hashes", b.tx_hashes},
                 {"transactions",b.txs},{"prev_hash",b.prev_block},{"next_hash",b.next_block},{"timestamp",b.timestamp},};
    }

    void from_json(const json& j, Block& b) {
        j.at("block_header").get_to(b.block_header);
        j.at("merkle_root").get_to(b.merkle_root);
        j.at("tx_hashes").get_to(b.tx_hashes);
        j.at("transactions").get_to(b.txs);
        j.at("prev_hash").get_to(b.prev_block);
        j.at("next_hash").get_to(b.next_block);
        j.at("timestamp").get_to(b.timestamp);
        j.at("height").get_to(b.height);

    }

};

class Blockchain{
    private:
        //
        std::shared_ptr<Identity> identity_;

        /////////////////////////////////////// BX - CONTAINERS ////////////////////////////////
        //!!!the block chain!!!
        std::vector<Block> block_chain_;

        //stores all blocks received from the network
        moodycamel::BlockingReaderWriterQueue<Block> received_blocks_;

        //stores all blocks ready to be broadcasted to the network
        moodycamel::BlockingReaderWriterQueue<std::string> broadcast_blocks_;
        std::mutex block_in_contention_;

        //stores votes for the block header to place at particular height
        //height : block_header: [node pks supporting header ....]
        std::map<int,std::unordered_map<string,std::vector<string>>> block_votes_;
        std::map<int,std::string> m_block_votes_;

        //all received proposed blocks are stored here
        //our block keys are tagged:  -header
        std::unordered_map<std::string,Block> proposed_block_mempool_;

        bool NewBX(std::string,long);

        void RequestBlocks(const std::string&);
        Block CreateBlock(std::vector<string>&,int);
        bool VerifyBlock(std::vector<std::string> tx_hashes,const std::string& merkle_root,const std::string& block_header,int height);

        std::vector<Block> GetBlocks(const std::string& from,const std::string& to);
        std::shared_ptr<Block> GetBlock(const std::string&);
        std::vector<std::string> GetBlocksJSON(const std::string& from,const std::string& to);

        void AddToChain(Block,bool);
        void Consensus();
        void TransactionPurge(long timestamp);
        void BlockVote(const Block& b,std::string iespk);
        std::mutex block_reorg_;

        std::thread block_worker_,rx_block_worker_,bx_block_worker_;
        bool block_worker_active_;
        void BlockWorker();
        void RXBlockWorker();
        void BXBlockWorker();
        //////////////////////////////////////////////////////////////////////////////////////////


        ////////////////////////////////// TX - CONTAINERS ///////////////////////////////////////////
        //stores a map of transactionhash : [node pks that support the tx ...]
        std::unordered_map<string,std::vector<std::string>> transaction_votes_;
        std::unordered_map<string,std::unordered_map<std::string,bool>> sent_votes_;

        //stores a map of node_pk: [txs...]
        std::unordered_map<string,std::vector<std::string>> sync_tx_votes_;

        //stores a map of transactionhash : {transaction data} that have passed concensus
        std::unordered_map<string,string> transaction_mempool_;
        std::vector<string> verified_tx_hash_mempool_;
        //queue of verified txs waiting to be added to the chain
        moodycamel::BlockingReaderWriterQueue<string> verified_transaction_q_;

        //stores transactions coming in from the network
        moodycamel::BlockingReaderWriterQueue<string> transaction_mem_q_;

        //stores sync transactions from the network for later processing
        moodycamel::BlockingReaderWriterQueue<string> sync_transaction_mem_q_;

        void TransactionVote(const std::string& tx_hash,const std::string& tx,const std::string& pk);
        bool NewTX(std::string);

        std::thread verification_worker_;
        std::thread sync_worker_;

        bool verifier_active_;
        void VerificationWorker();

        bool sync_worker_active_;
        void SyncWorker();
        void CreateTransaction();
        //////////////////////////////////////////////////////////////////////////////////////////


        /////////////////////////////// DISCOVERY/AUTH - CONTAINERS /////////////////////////////////////////
        std::unordered_map<string,string> auth_solutions_;

        //stores  a map of node_ids against public key.
        std::unordered_map<string,int> known_nodes_ies_;
        std::unordered_map<string,int> known_nodes_dsa_;
        std::unordered_map<string,int> authenticated_nodes_ies_;

        void AddKnownNode(const std::string& ies_pk,const std::string& dsa_pk);
        void AuthNode(const std::string& ies_pk);
        void Announce(const std::function<void(bool)>& cb);
        void Announce(const std::string& dsapk,const std::function<void(bool)>& cb);
        bool verifyPK(const string& ies,const string& dsa);
        bool CheckSolution(const std::string& ies_pk,const std::string& proposed);
        void AddChallenge(const std::string& ies_pk,const std::string& solution);
        ///////////////////////////////////////////////////////////////////////////////////////////


        ///////////////////// FORKING ///////////////////////////////////////////
        //stores fork_hash: [pks...]
        std::unordered_map<std::string,std::vector<std::string>> fork_votes_;
        std::unordered_map<std::string,std::vector<std::string>> close_votes_;
        std::unordered_map<std::string,std::vector<std::string>> init_votes_;

        //stores a map of node_id_ : int
        //total votes for each known node
        std::unordered_map<string,int> node_votes_;
        std::shared_ptr<Logger> mlogger_;
        std::mutex fork_m;
        void ForkVote(const Block&,const std::string&);
        void CloseVote(const Block&,const std::string&);
        void InitVote(const Block&,const std::string&);

        ///////////////////////////////// CONCURRENCY PRIMITIVES /////////////////////
        std::shared_ptr<std::condition_variable> cond;
        std::mutex mutex;

        void DirectMessage(const std::string& ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        void InternalMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        bool VerifyMessage(const nlohmann::json&);

        ////////////////////////////////////////////////////////////////////////////

        std::map<int,std::unordered_map<std::string,std::vector<std::string>>> block_rq_votes_;
        std::map<int,std::unordered_map<std::string,Block>> block_rq_mem_;
        Block& RetreiveBlock(int height);
        void BXRQVote(const Block& b,const std::string& iespk);
        Block CreateGenesis(std::vector<std::string>& txs);
        void StartWorkers();
        bool running_ = false;

        
    public:
        Blockchain(NodeConf dht_conf,std::shared_ptr<Identity> id,std::shared_ptr<Logger> logger){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = logger;
            dht_net_ = std::make_unique<DHTNode>(dht_conf,logger);
            identity_ = id;
        };
        ~Blockchain()= default;
        std::unique_ptr<DHTNode> dht_net_;
        std::string DHTRoutingTable();
        void Start();
        void DHTNodes();
        void AddKnownNodes(const std::string& path);
        bool IsRunning();
        void BroadcastTransaction();
        void PrintTX();
        void PrintBlocks();
        void PrintNodes();
};

#endif