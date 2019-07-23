//
// Created by emok on 5/21/19.
//

#ifndef E_VOTE_LITECHAIN_H
#define E_VOTE_LITECHAIN_H
#include "blockchain.hpp"
#include <typeinfo>


class Litechain {//{
    private:
        std::shared_ptr<Identity> identity_;
        std::shared_ptr<std::condition_variable> cond;
        std::shared_ptr<Logger> mlogger_;
        std::mutex mutex,fork_m;
        bool running,init_consensus_reached_ = false;
        std::unordered_map<string,string> auth_solutions_;

        //stores  a map of node_ids against public key.
        std::unordered_map<string,int> known_nodes_ies_;
        std::unordered_map<string,int> known_nodes_dsa_;
        std::unordered_map<string,int> authenticated_nodes_ies_;

        std::unordered_map<std::string,std::vector<std::string>> fork_votes_;
        std::unordered_map<std::string,std::vector<std::string>> close_votes_;
        std::unordered_map<std::string,std::vector<std::string>> init_votes_;

        std::map<int,std::unordered_map<std::string,std::vector<std::string>>> block_rq_votes_;
        std::map<int,std::unordered_map<std::string,Block>> block_rq_mem_;
        std::unordered_map<std::string,std::string> transaction_mem_;
        std::unordered_map<std::string,std::string> fork_transaction_mem_;

        std::unique_ptr<DHTNode> dht_net_;
        void DirectMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);

        std::map<int,Block> block_mempool_;


        void AuthNode(const std::string& ies_0pk);
        bool CheckSolution(const std::string& ies_pk,const std::string& proposed);
        bool VerifyMessage(const nlohmann::json& jsonObj);
        bool verifyPK(const string& ies_publicKey,const string& dsa_publicKey);
        void Announce(const std::string& dsapk,const std::function<void(bool)>& cb);
        void AddChallenge(const std::string& ies_pk,const std::string& solution);
        void CloseVote(const Block& b,const std::string& iespk);
        void ForkVote(const Block& b,const std::string& iespk);
        void InitVote(const Block& b,const std::string& iespk);
        void BXRQVote(const Block& b,const std::string& iespk);
        void StoreBlock(Block b);
        void InternalMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb);
        void AddKnownNode(const std::string& ies_pk,const std::string& dsa_pk);
        void Announce(const std::function<void(bool)>& cb);
        void CacheTX(const std::string&,const std::string&,bool);
        void InitializeAuthenticationChannels();
        void InitializeInternalChannels();
        void InitializeExplorerChannels();
        void InitializeIntegrationChannels();



    public:
        Litechain(const string& dht_conf,const string& identity){
            cond = std::make_shared<std::condition_variable>();
            mlogger_ = std::make_shared<Logger>();

            NodeConf conf;
            std::ifstream conf_file(dht_conf);
            json parsed;
            conf_file >> parsed;

            conf.node_id = parsed["NODE_ID"];
            conf.main = parsed["MAINNET"];
            conf.mainnet_addr = parsed["MAINNET_ADDR"];
            conf.testnet_addr = parsed["TESTNET_ADDR"];
            conf.port = parsed["PORT"];
            conf.testnet_port = parsed["TESTNET_PORT"];
            conf.mainnet_port = parsed["MAINNET_PORT"];

            dht_net_ = std::make_unique<DHTNode>(conf,mlogger_);
            identity_ = std::make_shared<Identity>(identity);
        };

        std::string DHTRoutingTable();
        void Start(bool explorer= false);
        void InitFork();
        void InitChain(const std::string&);
        void CloseChain();
        std::string SeedKeys(const string& seed,bool deterministic);
        std::string GetBlock(int height,std::string chain,bool explorer);
        std::string GetTransactions();
        std::string GetTransaction(std::string pubkey,std::string chain);
        void RequestTransaction(std::string pubkey, std::string chain);
        void BroadcastTX(const string& tx);
        void BlockRQ(nlohmann::json);
        void ExplorerBlockRQ(nlohmann::json);
        void AddKnownNodes(const std::string& path);

};


#endif //E_VOTE_LITECHAIN_H
