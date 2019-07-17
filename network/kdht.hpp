#ifndef KDHT_HPP
#define KDHT_HPP

#include <iostream>
#include <opendht.h>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <map>
#include "logger/log.hpp"
#include "utils/json.hpp"

struct NodeConf{
    int port;
    bool main;
    std::string node_id;
    std::string mainnet_addr;
    std::string testnet_addr;
    std::string testnet_port;
    std::string mainnet_port;

};

class DHTNode{
    private:
        std::string node_id_;
        int port_;

        dht::DhtRunner node_;

        std::shared_ptr<std::condition_variable> cond_;
        std::shared_ptr<Logger> mlogger_;
        std::mutex mmutex_;
        std::string mainnet_;
        std::string testnet_;
        bool running_ = false; 
        bool bootstrap_ = false;
        bool _mainnet_ = false;
        std::string bootstrap_port_;

        void Register();
        
        
    public:
        std::string internal_channel_;
        std::string announce_channel_;
        std::string tx_channel_;
        std::string block_channel_;
        std::string sync_channel_;
        std::string fork_channel_;
        std::string close_channel_;
        std::string init_channel_;
        std::string bxrq_channel_;
        std::string bxrx_channel_;


        DHTNode(NodeConf conf,std::shared_ptr<Logger> logger):mlogger_(logger){
            mainnet_ = conf.mainnet_addr;
            testnet_ = conf.testnet_addr;
            _mainnet_ = conf.main;
            node_id_ = conf.node_id;
            port_ = conf.port;
            bootstrap_port_ = (conf.main) ? conf.mainnet_port: conf.testnet_port;
        }
        DHTNode(){};
        ~DHTNode(){};

        DHTNode(const DHTNode& old){
            mainnet_ = old.mainnet_;
            testnet_ = old.testnet_;
            _mainnet_ = old._mainnet_;
            node_id_ = old.node_id_;
            cond_ = old.cond_;
            mlogger_ = old.mlogger_;
        }
        
        bool IsRun(){
            return running_;
        }
        bool Start();
        
        void Put(const std::string&,const std::string&,std::function<void(bool)>);
        void Get(const std::string&,std::function<void(std::vector<uint8_t>)>);

        void AnnounceChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void BXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void TXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        
        //starts a thread that listens for messages on h(node_id_)
        //for authentication,direct messages etc...
        void InternalChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);

        //
        void ForkChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void BXRQChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void BXRXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void ChainInitChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);
        void ChainCloseChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)>);

        
        
        std::string RoutingTable();
        void NodeStats();

};

#endif