#include <exception>
#include <sys/socket.h>
#include "kdht.hpp"
#include "opendht.h"
#include "logger/log.hpp"
#include "utils/json.hpp"
#include <exception>
#include <sys/socket.h>
// #include <msgpack.hpp>


bool DHTNode::Start(){
    try{
        this->mlogger_->Debug("Initializing node");
        node_.run(port_,dht::crypto::generateIdentity(node_id_),true);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
        return false;
        
    }
    running_ = true;
    
    //check for public address
    auto addrs = node_.getPublicAddressStr();
    int numAddrs = static_cast<int>(addrs.size());

    if (numAddrs == 0){
        //No public IP, can't directly participate in the network without port forwarding.
        //Try to connect to node reachable via public address
        //Force bootstrap to evote mainnet/testnet
        this->mlogger_->Debug("No public address detected. Confifure router port forwarding and rerun with {-portforward}");
        this->mlogger_->Info("Bootstrapping to evote ",(_mainnet_?"mainnet":"testnet")," at",(_mainnet_?mainnet_:testnet_));
        node_.bootstrap((_mainnet_?mainnet_:testnet_),"4333");

        //if fail,(network is dead)
    }else{
        this->mlogger_->Debug("Public address detected ",addrs[0]);
        //check if network ddns address is taken
        try{
            this->mlogger_->Info("Bootstrapping to evote ",(_mainnet_?"mainnet":"testnet"),"at ",(_mainnet_?mainnet_:testnet_));
            node_.bootstrap((_mainnet_?mainnet_:testnet_),"4333");
        }catch(const exception& e){
            //TODO:register as dynamic dns address owner
            this->mlogger_->Error("Bootstrap failed, taking ownership of ddns address");
 
            return false;
        }   
        
    }
    return true;
}

void DHTNode::UnverifiedChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(unverified_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::VerifiedChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(verified_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::InternalChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(internal_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::Put(std::string key,int type,nlohmann::json data,std::function<void(bool)> cb){
    try{
        nlohmann::json j;
        j["data"] = "DATA";//data.dump();
        j["signature"] = "RSA_SIGNED";

        std::string the_data = j.dump();
        
        auto p = std::make_unique<dht::Value>((const uint8_t*)the_data.data(), the_data.size());
        // auto p = std::make_unique<dht::Value>(packed);

        node_.put(key,p,cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
        cb(false);
    }
}


void DHTNode::Get(std::string key,std::function<void(std::vector<uint8_t>)> cb){
    this->node_.get<std::vector<uint8_t>>(dht::InfoHash::get(key),[&](std::vector<uint8_t>&& data)->bool{
        cb(data);
        return true;
    });
}

std::string DHTNode::RoutingTable(){
    return this->node_.getRoutingTablesLog(AF_INET);
}

dht::NodeStats DHTNode::NodeStats(){
    return this->node_.getNodesStats(AF_INET);
}