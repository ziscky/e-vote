#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP

#define TX_BROADCAST 0
#define NODE_AUTH 1
#define BX_BROADCAST 2

#define AUTH_CHALLENGE 0
#define AUTH_SOLUTION 1


#include "network/kdht.hpp"
#include "network/btcp.hpp"
#include "utils/json.hpp"
#include "logger/log.hpp"
#include <map>
#include <vector>

using json = nlohmann::json;

struct Block{
    std::string block_header;
    std::string merkle_root;
    std::vector<std::string> tx_hashes;
    json data;
    std::string prev_block;
    std::string next_block;
    uint64_t timestamp;

};

class Blockchain{
    private:
        
        std::unique_ptr<BitcoinProtocol> btcp_net_;

        //!!!the block chain!!!
        std::vector<Block> block_chain_;
        
        //stores a map of transactionhash : {node_id:1/-1}
        //to approve a transaction, node registers 1
        //to reject a transaction, node registers -1
        std::unordered_map<string,std::unordered_map<string,int>> transaction_votes_;
        
        //stores a map of transactionhash : {transaction data}
        std::unordered_map<string,std::vector<uint8_t>> verified_transactions_;

        //stores a map of node_id_ : int
        //total votes for each known node
        std::unordered_map<string,int> node_votes_;

        //stores  a map of node_ids against public key.
        std::vector<string> known_nodes_;

        std::shared_ptr<std::condition_variable> cond;

        std::shared_ptr<Logger> mlogger_;

        //included in callback for 
        void ReceiveTransaction();
        void ReceiveBlock();
        void AuthNode(const nlohmann::json&);

        void BroadcastTransaction();
        void BroadcastBlock();
        
        void CreateBlock();
        void CreateTransaction();

        bool verifyPK(const string&);
        

        bool running_ = false;

        
    public:
        Blockchain(NodeConf dht_conf,std::shared_ptr<Logger> logger){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = logger;
            dht_net_ = std::make_unique<DHTNode>(dht_conf,cond,logger);
        };
        ~Blockchain(){};
        std::unique_ptr<DHTNode> dht_net_;
        void Start();
        std::string DHTRoutingTable();
        void DHTNodes();
        bool IsRunning();

};

#endif