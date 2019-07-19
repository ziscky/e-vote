#include <exception>
#include <sys/socket.h>
#include <netdb.h>
#include "kdht.hpp"
#include "opendht.h"
#include "logger/log.hpp"
#include "utils/json.hpp"

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
        this->mlogger_->Info("Bootstrapping to evote ",(_mainnet_?"mainnet":"testnet")," at ",(_mainnet_?mainnet_:testnet_));
        node_.bootstrap((_mainnet_?mainnet_:testnet_),this->bootstrap_port_);

        //if fail,(network is dead)
    }else{
        this->mlogger_->Debug("Public address detected ",addrs[0]);
        //check if network ddns address is taken
        try{
            this->mlogger_->Info("Bootstrapping to evote ",(_mainnet_?"mainnet":"testnet"),"at ",(_mainnet_?mainnet_:testnet_));
            node_.bootstrap((_mainnet_?mainnet_:testnet_),std::to_string(this->port_));
        }catch(const exception& e){
            //TODO:register as dynamic dns address owner
            this->mlogger_->Error("Bootstrap failed, taking ownership of ddns address");
 
            return false;
        }   
        
    }
    return true;
}

void DHTNode::TXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(tx_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::BXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(block_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::InternalChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(internal_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::AnnounceChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(announce_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::ReactAnnounceChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(react_announce_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::BXRQChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(bxrq_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::TXRQChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(txrq_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::TXRXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(txrx_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}


void DHTNode::BXRXChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(bxrx_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::ForkChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(fork_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

//
void DHTNode::ChainInitChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(init_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}
void DHTNode::ChainCloseChannel(std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&)> cb){
    try{
        this->node_.listen(dht::InfoHash::get(close_channel_),cb);
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
    }
}

void DHTNode::Put(const std::string& key,const std::string& data,std::function<void(bool)> cb){
    try{
        auto p = std::make_unique<dht::Value>((const uint8_t*)data.data(), data.size());
        // auto p = std::make_unique<dht::Value>(packed);

        node_.put(key,p,cb);
        // node_.dumpTables();
        
    }catch(const exception& e){
        this->mlogger_->Error(e.what());
        cb(false);
    }
}


void DHTNode::Get(const std::string& key,std::function<void(std::vector<uint8_t>)> cb){
    this->node_.get<std::vector<uint8_t>>(dht::InfoHash::get(key),[&](std::vector<uint8_t>&& data)->bool{
        cb(data);
        return true;
    });
}

std::string DHTNode::RoutingTable(){
    return this->node_.getRoutingTablesLog(AF_INET);
}

void DHTNode::NodeStats(){
    std::vector<dht::NodeExport> nodes = this->node_.exportNodes();
    std::for_each(nodes.begin(),nodes.end(),[&](dht::NodeExport node){
        char host[NI_MAXHOST];
        char port[NI_MAXSERV];

        int rc = getnameinfo((struct sockaddr *)&node.ss, node.sslen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
        if(rc != 0){
            this->mlogger_->Error("Failed to decode ip:port from socket");
            return;
        }
        std::string host_str(host);
        std::string port_str(port);

        std::cout<<host_str<<":"<<port_str<<endl;


    });
}