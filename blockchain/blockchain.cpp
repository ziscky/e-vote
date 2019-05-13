#include "blockchain.hpp"
#include "opendht.h"
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
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
    this->dht_net_->announce_channel_ = this->identity_->DSAPublicKey();
    this->dht_net_->internal_channel_ = this->identity_->IESPublicKey();
    this->dht_net_->Start();
    
    this->Announce([&](bool success){
        std::cout<<"Announce: "<<success<<std::endl;
    });

    this->dht_net_->AnnounceChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired)->bool{
        auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
        
        
        if(!utils::checkParams(jsonObj,{"iespk"}))
            return false;

        auto ies_publicKey = jsonObj["iespk"].get<std::string>();

        if(this->identity_->IESPublicKey() == ies_publicKey)
            return false;

        if(this->known_nodes_ies_.find(ies_publicKey) == this->known_nodes_ies_.end())
            return false;

        if(this->authenticated_nodes_ies_.find(ies_publicKey) != this->authenticated_nodes_ies_.end())
            return false;

        this->mlogger_->Debug("Received Announcement",jsonObj);
        //TODO: GEN RANDOM CHALLENGE
        nlohmann::json payload;
        payload["data"]["challenge"] = "cipher";

        this->AddChallenge(ies_publicKey,"cipher");

        this->DirectMessage(ies_publicKey,payload,AUTH_CHALLENGE,[&](bool success){
            //success
            this->mlogger_->Debug("CHALLENGE SEND: ",success);
        });
        return true;
    });

    this->dht_net_->InternalChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data, bool expired)->bool{
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            
            if(!utils::checkParams(jsonObj,{"dsapk","iespk","data","signature","type"}))
                return false;
            
            string ies_publicKey = jsonObj["iespk"].get<string>();
            string dsa_publicKey = jsonObj["dsapk"].get<string>();
            
            if(this->identity_->IESPublicKey() == ies_publicKey)
                return false;   

            //check if known node
            if(!(this->verifyPK(ies_publicKey,dsa_publicKey))){
                this->mlogger_->Error("Unknown public key");
                return false;
            }

            //verify sent data
            if (!this->identity_->VerifyData(dsa_publicKey,jsonObj["data"].get<std::string>(),jsonObj["signature"].get<std::string>())){
                this->mlogger_->Error("Verification failed...");
                return false;
            }
            this->mlogger_->Debug("Verification success....");

            switch(jsonObj["type"].get<int>()){
                case TX_BROADCAST:
                    // this->ReceiveTransaction();
                case BX_BROADCAST:
                    // this->ReceiveBlock();
                case AUTH_CHALLENGE:
                    {                   
                        this->mlogger_->Debug("CHALLENGE RECIEVED");
                        //received authentication challenge from alleged known node
                        try{
                            nlohmann::json parsed,response;
                            auto dat = jsonObj["data"].get<std::string>();
                            std::cout<<dat<<std::endl;
                            
                            parsed.parse(this->identity_->DecryptData(dat));

                            if(utils::checkParams(parsed,{"challenge"}))
                                return false;
                            
                            response["solution"] = parsed["challenge"].get<std::string>();

                            this->DirectMessage(ies_publicKey,response,AUTH_SOLUTION,[&](bool){
                                //success
                            });
                            

                        }catch(std::exception& e){
                            this->mlogger_->Error(e.what());
                            return false;
                        }            

                    }
                    
                case AUTH_SOLUTION:
                    {
                        this->mlogger_->Debug("SOLUTION RECIEVED");
                        try{
                            nlohmann::json parsed,response;
                            auto dat = jsonObj["data"].get<std::string>();
                            parsed.parse(this->identity_->DecryptData(dat));

                            if(utils::checkParams(parsed,{"solution"}))
                                return false;
                            
                            if(!this->CheckSolution(ies_publicKey,parsed["solution"].get<std::string>())){
                                return false;
                            }

                            this->AuthNode(ies_publicKey);



                        }catch(std::exception& e){
                            this->mlogger_->Error(e.what());
                            return false;
                        }       
                        
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

    this->running_ = true;
    
}

//
//send auth challenge and expect response
void Blockchain::AuthNode(std::string ies_pk){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->authenticated_nodes_ies_[ies_pk] = 1;
    this->auth_solutions_.erase(ies_pk);
}

void Blockchain::AddKnownNode(std::string ies_pk,std::string dsa_pk){
    std::lock_guard<std::mutex> lck(this->mutex);

    this->known_nodes_ies_[ies_pk] = 1;
    this->known_nodes_dsa_[dsa_pk] = 1;
}

void Blockchain::AddKnownNodes(std::string path){
    std::ifstream f(path);
    nlohmann::json j;
    f >> j;


    auto ies_pks = j["nodes"].get<std::vector<std::unordered_map<std::string,std::string>>>();
    for(auto& node: ies_pks){
        auto ies = node["ies"];
        auto dsa = node["dsa"];

        this->AddKnownNode(ies,dsa);
    }
    
    
}

void Blockchain::AddChallenge(std::string ies_pk,std::string solution){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->auth_solutions_[ies_pk] = solution;
}


void Blockchain::DirectMessage(std::string dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    this->mlogger_->Debug("Sending: ",data["data"].dump());
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = type;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    std::cout<<cipher<<endl;
    auto d = payload.dump();
    this->dht_net_->Put(dest_ies_pk,payload.dump(),cb);
}

void Blockchain::Announce(std::function<void(bool)> cb){
    this->mlogger_->Debug("Announcing....");

    nlohmann::json payload;
    payload["iespk"] = this->identity_->IESPublicKey();

    for(auto& node: this->known_nodes_dsa_){
        if(node.first == this->identity_->DSAPublicKey())
            continue;       
        this->dht_net_->Put(node.first,payload.dump(),cb);
    }
    
}

bool Blockchain::IsRunning(){
    return this->dht_net_->IsRun() && this->running_;
}

bool Blockchain::CheckSolution(std::string ies_pk,std::string proposed){
    if(this->auth_solutions_.find(ies_pk) == this->auth_solutions_.end())
        return false;
    
    return this->auth_solutions_[ies_pk] == proposed;
}

std::string Blockchain::DHTRoutingTable(){
    return this->dht_net_->RoutingTable();
}

void Blockchain::DHTNodes(){
    this->dht_net_->NodeStats();
}


bool Blockchain::verifyPK(const string& ies_publicKey,const string& dsa_publicKey){
    return (this->known_nodes_ies_.find(ies_publicKey) != this->known_nodes_ies_.end()) && (this->known_nodes_dsa_.find(dsa_publicKey) != this->known_nodes_dsa_.end()); 
}
