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
    std::string unverified_channel;
    std::string verified_channel;
    std::string internal_channel;
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
        std::string internal_channel_;

        bool running_ = false; 
        bool bootstrap_ = false;
        bool _mainnet_ = false;

        void Register();
        
        
    public:
        DHTNode(NodeConf conf,std::shared_ptr<std::condition_variable> c,std::shared_ptr<Logger> logger):cond_(c),mlogger_(logger){
            unverified_channel_ = conf.unverified_channel;
            verified_channel_ = conf.verified_channel;
            internal_channel_ = conf.internal_channel;
            mainnet_ = conf.mainnet_addr;
            testnet_ = conf.testnet_addr;
            _mainnet_ = conf.main;
            node_id_ = conf.node_id;
            port_ = conf.port;
        }

        ~DHTNode(){};

        DHTNode(const DHTNode& old){
            unverified_channel_ = old.unverified_channel_;
            verified_channel_ = old.verified_channel_;
            internal_channel_ = old.internal_channel_;
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
        
        void Put(std::string,int,nlohmann::json,std::function<void(bool)>);
        void Get(std::string,std::function<void(std::vector<uint8_t>)>);
        void UnverifiedChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)>);
        void VerifiedChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)>);
        //starts a thread that listens for messages on h(node_id_)
        //for authentication,direct messages etc...
        void InternalChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)>);
        std::string RoutingTable();
        dht::NodeStats NodeStats(); 
        

        



};

#endif