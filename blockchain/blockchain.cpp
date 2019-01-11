#include "blockchain.hpp"
#include "opendht.h"
#include "utils/json.hpp"
#include "utils/utils.hpp"
#include <vector>
#include <iostream>
#include <string>
#include <msgpack.hpp>


void Blockchain::Start(){
    if(this->IsRunning()){
        return;
    }
    this->dht_net_->Start();

    //TODO:: PKCS authentication of origin node
    //std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)> cb
    this->dht_net_->InternalChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired){
    
        // //{"id":0,"dat":{"body":{"type":0,"data":"TEXT"}}}
        // auto obj = msgpack::v3::unpack( (const char*)data[0]->data.data(), data[0]->data.size());
        // if(obj->is_nil()){
        //     this->mlogger_->Error("Nil BLOB");
        //     return true;
        // }
        // if(obj->type != msgpack::type::MAP){
        //     //unsupported
        // }
        // this->mlogger_->Info("L1",obj.get());

        // auto payload_blob = utils::findMapValue(obj.get(),"dat");
        // if(payload_blob->type != msgpack::type::MAP){
        //     //unsupported
            
        // }
        // this->mlogger_->Info("L2 ",*payload_blob);
        
        // payload_blob = utils::findMapValue(*payload_blob,"body");
        // if(payload_blob->type != msgpack::type::MAP){
        //     //unsupported
            
        // }
        // this->mlogger_->Info("L3 ",*payload_blob);


        // auto data_blob = utils::findMapValue(*payload_blob,"data");
        // std::vector<uint8_t> data_ = utils::unpackBlob(*data_blob);
        // std::string data_str{data_.begin(),data_.end()};
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            this->mlogger_->Debug("Received msg on internal channel ",data.size()," bytes from ",jsonObj.dump());
            
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }

        // nlohmann::json fmpack = nlohmann::json::from_bson(data[0]->data);
        
        
        return true;
    });

    //TODO:: Consider transaction vote
    this->dht_net_->VerifiedChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired){
        this->mlogger_->Debug("Received msg on verified channel ",data.size()," bytes");
        return true;
    });

    // //TODO:: Verify transaction
    this->dht_net_->UnverifiedChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired){
        this->mlogger_->Debug("Received msg on unverified channel ",data.size()," bytes");
        return true;
    });

    this->running_ = true;
    
}

void Blockchain::AuthNode(){
    this->mlogger_->Debug("Authenticating node");
}

bool Blockchain::IsRunning(){
    return this->dht_net_->IsRun() && this->running_;
}

std::string Blockchain::DHTRoutingTable(){
    return this->dht_net_->RoutingTable();
}

dht::NodeStats Blockchain::DHTNodes(){
    return this->dht_net_->NodeStats();
}