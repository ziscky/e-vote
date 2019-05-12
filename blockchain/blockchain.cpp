#include "blockchain.hpp"
#include "opendht.h"
#include "utils/json.hpp"
#include "utils/utils.hpp"
#include <vector>
#include <iostream>
#include <string>
#include <msgpack.hpp>

/*
It is possible to transfer into a block, but not in a way that bypasses declarations with initialization.
A program that jumps from a point where a local variable with automatic storage duration is not in scope
to a point where it is in scope is ill-formed unless the variable has POD type (3.9) and is declared without an initializer
*/
void Blockchain::Start(){
    if(this->IsRunning()){
        return;
    }
    this->dht_net_->Start();

    //TODO:: PKCS authentication of origin node
    //std::function<bool(const std::vector<std::shared_ptr<dht::Value>>&, bool)> cb
    this->dht_net_->InternalChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired)->bool{
    
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(jsonObj["type"].is_null())
                return false;
            switch(jsonObj["type"].get<int>()){
                case TX_BROADCAST:
                    this->ReceiveTransaction();
                case BX_BROADCAST:
                    this->ReceiveBlock();
                default:
                    return false;
                
            }
            
            this->mlogger_->Debug("Received msg on internal channel ",data[0]->data.size()," bytes from ",jsonObj.dump());
            
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        
        return true;
    });

    //TODO:: Consider transaction vote
    this->dht_net_->VerifiedChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired){
        this->mlogger_->Debug("Received msg on verified channel ",data.size()," bytes");
         try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(jsonObj["type"].is_null())
                return false;
            switch(jsonObj["type"].get<int>()){
                case AUTH_CHALLENGE:
                {
                    if(utils::checkParams(jsonObj,{"pk","challenge"}))
                        return false;
                    //received authentication challenge from alleged known node

                    //1. check if node's public key is registered                    
                    string publicKey = jsonObj["pk"].get<string>();
                    if(!(this->verifyPK(publicKey))){
                        this->mlogger_->Error("Unknown public key");
                        return false;
                    }

                    //2.solve challenge
                    //3.sign solution
                    //4.encrypt solution
                    //5.broadcast solution 
                    

                    

                }
                    
                case AUTH_SOLUTION:
                {
                    if(utils::checkParams(jsonObj,{"pk","solution"}))
                        return false;
                    //1. decrypt solution
                    //2. check known pk
                    //3. verify signature
                    //4. add to trusted nodes
                }
                    
                default:
                    return false;
                
            }
            
            this->mlogger_->Debug("Received msg on internal channel ",data[0]->data.size()," bytes from ",jsonObj.dump());
            
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }

        return true;
    });

    // //TODO:: Verify transaction
    this->dht_net_->UnverifiedChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired){
        this->mlogger_->Debug("Received msg on unverified channel ",data.size()," bytes");
        return true;
    });

    this->running_ = true;
    
}

//
//send auth challenge and expect response
void Blockchain::AuthNode(const nlohmann::json& data){
    this->mlogger_->Debug("Authenticating node");
    // data[""]
}

bool Blockchain::IsRunning(){
    return this->dht_net_->IsRun() && this->running_;
}

std::string Blockchain::DHTRoutingTable(){
    return this->dht_net_->RoutingTable();
}

void Blockchain::DHTNodes(){
    this->dht_net_->NodeStats();
}


bool Blockchain::verifyPK(const string& publicKey){
    for(auto& pk : this->known_nodes_){
        if(pk == publicKey){
            return true;
        }
    }
    return false;
}
