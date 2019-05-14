#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP

#define TX_BROADCAST 0
#define NODE_AUTH 1
#define BX_BROADCAST 2
#define AUTH_CHALLENGE 3
#define AUTH_SOLUTION 4

#define BLOCK_MAX 0


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
    std::unordered_map<std::string,std::string> txs;
    std::string prev_block;
    std::string next_block;
    long timestamp;

    void to_json(json& j, const Block& b) {
        j = json{{"block_header", b.block_header}, {"merkle_root", b.merkle_root}, {"tx_hashes", b.tx_hashes},
                 {"transactions",b.txs},{"prev_hash",b.prev_block},{"next_hash",b.next_block},{"timestamp",b.timestamp}};
    }

    void from_json(const json& j, Block& b) {
        j.at("block_header").get_to(b.block_header);
        j.at("merkle_root").get_to(b.merkle_root);
        j.at("tx_hashes").get_to(b.tx_hashes);
        j.at("transactions").get_to(b.txs);
        j.at("prev_hash").get_to(b.prev_block);
        j.at("next_hash").get_to(b.next_block);
        j.at("timestamp").get_to(b.timestamp);

    }

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
        std::unordered_map<string,string> verified_transactions_;

        std::unordered_map<string,string> auth_solutions_;

        //stores a map of node_id_ : int
        //total votes for each known node
        std::unordered_map<string,int> node_votes_;

        //stores  a map of node_ids against public key.
        std::unordered_map<string,int> known_nodes_ies_;
        std::unordered_map<string,int> known_nodes_dsa_;
        void AddKnownNode(const std::string& ies_pk,const std::string& dsa_pk);
        
        
        std::unordered_map<string,int> authenticated_nodes_ies_;
        void AuthNode(const std::string& ies_pk);

        std::shared_ptr<std::condition_variable> cond;

        std::shared_ptr<Logger> mlogger_;

        std::mutex mutex;


        void BroadcastTransaction();
        void BroadcastBlock();
        
        void CreateBlock();
        void CreateTransaction();

        void Announce(const std::function<void(bool)>& cb);

        bool verifyPK(const string& ies,const string& dsa);
        
        void DirectMessage(const std::string& ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        bool CheckSolution(const std::string& ies_pk,const std::string& proposed);
        void AddChallenge(const std::string& ies_pk,const std::string& solution);

        void TransactionVote(const std::string& tx_hash,const std::string& pk,int vote);
        void BlockVote();
        void AddVerifiedTx(const std::string& tx_hash,const std::string& data);

        bool running_ = false;

        
    public:
        Blockchain(NodeConf dht_conf,std::shared_ptr<Identity> id,std::shared_ptr<Logger> logger){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = logger;
            dht_net_ = std::make_unique<DHTNode>(dht_conf,cond,logger);
            identity_ = id;

        };
        ~Blockchain()= default;
        std::unique_ptr<DHTNode> dht_net_;
        void Start();
        std::string DHTRoutingTable();
        void DHTNodes();
        void AddKnownNodes(const std::string& path);
        bool IsRunning();

};

#endif