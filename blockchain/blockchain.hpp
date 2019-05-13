#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP

#define TX_BROADCAST 0
#define NODE_AUTH 1
#define BX_BROADCAST 2
#define AUTH_CHALLENGE 3
#define AUTH_SOLUTION 4


#include "network/kdht.hpp"
#include "security/identity.hpp"
#include "utils/utils.hpp"
#include <map>
#include <vector>
#include <mutex>

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
        std::shared_ptr<Identity> identity_;
        // std::unique_ptr<BitcoinProtocol> btcp_net_;

        //!!!the block chain!!!
        std::vector<Block> block_chain_;
        
        //stores a map of transactionhash : {node_id:1/-1}
        //to approve a transaction, node registers 1
        //to reject a transaction, node registers -1
        std::unordered_map<string,std::unordered_map<string,int>> transaction_votes_;
        
        //stores a map of transactionhash : {transaction data}
        std::unordered_map<string,std::vector<uint8_t>> verified_transactions_;

        std::unordered_map<string,string> auth_solutions_;

        //stores a map of node_id_ : int
        //total votes for each known node
        std::unordered_map<string,int> node_votes_;

        //stores  a map of node_ids against public key.
        std::unordered_map<string,int> known_nodes_ies_;
        std::unordered_map<string,int> known_nodes_dsa_;
        void AddKnownNode(std::string ies_pk,std::string dsa_pk);
        
        
        std::unordered_map<string,int> authenticated_nodes_ies_;
        void AuthNode(std::string ies_pk);

        std::shared_ptr<std::condition_variable> cond;

        std::shared_ptr<Logger> mlogger_;

        std::mutex mutex;

        //included in callback for 
        void ReceiveTransaction();
        void ReceiveBlock();
        

        void BroadcastTransaction();
        void BroadcastBlock();
        
        void CreateBlock();
        void CreateTransaction();

        void Announce(std::function<void(bool)> cb);

        bool verifyPK(const string& ies,const string& dsa);
        
        void DirectMessage(std::string ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        bool CheckSolution(std::string ies_pk,std::string proposed);
        void AddChallenge(std::string ies_pk,std::string solution);

        bool running_ = false;

        
    public:
        Blockchain(NodeConf dht_conf,std::shared_ptr<Identity> id,std::shared_ptr<Logger> logger){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = logger;
            dht_net_ = std::make_unique<DHTNode>(dht_conf,cond,logger);
            identity_ = id;

            std::cout<<identity_->IESPublicKey()<<std::endl;
        };
        ~Blockchain(){};
        std::unique_ptr<DHTNode> dht_net_;
        void Start();
        std::string DHTRoutingTable();
        void DHTNodes();
        void AddKnownNodes(std::string path);
        bool IsRunning();

};

#endif