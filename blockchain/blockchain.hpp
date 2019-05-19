#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP

#define TX_BROADCAST 0
#define NODE_AUTH 1
#define BX_BROADCAST 2
#define AUTH_CHALLENGE 3
#define AUTH_SOLUTION 4
#define BX_UPDATE 5
#define BLOCK_MAX 3


#include "network/kdht.hpp"
#include "security/identity.hpp"
#include "utils/utils.hpp"
#include "utils/readerwriterqueue.h"
#include "utils/atomicops.h"


#include <map>
#include <vector>
#include <mutex>
#include <thread>

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

        //stores proposed created blocks
        moodycamel::ReaderWriterQueue<Block> proposed_blocks_;
        int proposed_blocks_size_;

        moodycamel::BlockingReaderWriterQueue<Block> received_blocks_;
        //stores votes for the block header to place at particular height
        //height : block_header: [node pks supporting header ....]
        std::map<int,std::unordered_map<string,std::vector<string>>> block_votes_;

        //all received proposed blocks are stored here
        std::unordered_map<std::string,Block> proposed_block_mempool_;

        bool NewBX(std::string,long);
        void BroadcastBlock(Block& block);
        void RequestBlocks(const std::string&);
        Block CreateBlock(std::vector<string>&);
        bool VerifyBlock(std::vector<std::string> tx_hashes,const std::string& merkle_root,const std::string& block_header,int height);

        std::vector<Block> GetBlocks(const std::string& from,const std::string& to);
        std::shared_ptr<Block> GetBlock(const std::string&);
        std::vector<std::string> GetBlocksJSON(const std::string& from,const std::string& to);

        void AddToChain(Block);

        std::thread block_worker_,rx_block_worker_;
        bool block_worker_active_;
        void BlockWorker();
        void RXBlockWorker();
        //////////////////////////////////////////////////////////////////////////////////////////


        ////////////////////////////////// TX - CONTAINERS ///////////////////////////////////////////
        //stores a map of transactionhash : [node pks that support the tx ...]
        std::unordered_map<string,std::vector<std::string>> transaction_votes_;
        std::unordered_map<string,std::unordered_map<std::string,bool>> sent_votes_;

        //stores a map of transactionhash : {transaction data} that have passed concensus
        std::unordered_map<string,string> transaction_mempool_;

        //queue of verified txs waiting to be added to the chain
        moodycamel::BlockingReaderWriterQueue<string> verified_transaction_q_;

        //stores transactions coming in from the network
        moodycamel::BlockingReaderWriterQueue<string> transaction_mem_q_

        ;

        void TransactionVote(const std::string& tx_hash,const std::string& tx,const std::string& pk);
        bool NewTX(std::string);

        std::thread verification_worker_;
        bool verifier_active_;
        void VerificationWorker();

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


        //stores a map of node_id_ : int
        //total votes for each known node
        std::unordered_map<string,int> node_votes_;
        std::shared_ptr<Logger> mlogger_;

        ///////////////////////////////// CONCURRENCY PRIMITIVES /////////////////////
        std::shared_ptr<std::condition_variable> cond;
        std::mutex mutex;

        void DirectMessage(const std::string& ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        bool VerifyMessage(const nlohmann::json&);

        ////////////////////////////////////////////////////////////////////////////

        bool running_ = false;

        
    public:
        Blockchain(NodeConf dht_conf,std::shared_ptr<Identity> id,std::shared_ptr<Logger> logger){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = logger;
            dht_net_ = std::make_unique<DHTNode>(dht_conf,cond,logger);
            identity_ = id;
            proposed_blocks_size_ = 0;

        };
        ~Blockchain()= default;
        std::unique_ptr<DHTNode> dht_net_;
        void Start();
        std::string DHTRoutingTable();
        void DHTNodes();
        void AddKnownNodes(const std::string& path);
        bool IsRunning();
        void BroadcastTransaction();
        void PrintTX();
        void PrintBlocks();

        void PrintNodes();
};

#endif