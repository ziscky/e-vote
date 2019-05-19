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
    std::string internal_channel;
    std::string announce_channel;
    std::string block_channel;
    std::string tx_channel;
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
        std::string unverified_channel_;
        std::string verified_channel_;

        bool running_ = false; 
        bool bootstrap_ = false;
        bool _mainnet_ = false;

        void Register();
        
        
    public:
        std::string internal_channel_;
        std::string announce_channel_;
        std::string tx_channel_;
        std::string block_channel_;
        DHTNode(NodeConf conf,std::shared_ptr<std::condition_variable> c,std::shared_ptr<Logger> logger):cond_(c),mlogger_(logger){
            tx_channel_ = conf.tx_channel;
            internal_channel_ = conf.internal_channel;
            announce_channel_ = conf.announce_channel;
            block_channel_ = conf.block_channel;
            mainnet_ = conf.mainnet_addr;
            testnet_ = conf.testnet_addr;
            _mainnet_ = conf.main;
            node_id_ = conf.node_id;
            port_ = conf.port;
        }

        ~DHTNode(){};

        DHTNode(const DHTNode& old){
            unverified_channel_ = old.unverified_channel_;
            tx_channel_ = old.tx_channel_;
            announce_channel_ = old.announce_channel_;
            block_channel_ = old.block_channel_;
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
        
        
        std::string RoutingTable();
        void NodeStats();
        

        



};

#endif