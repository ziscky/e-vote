#include <utility>

#include "blockchain.hpp"
#include "opendht.h"
#include "merkle.hpp"
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
            return true;

        auto ies_publicKey = jsonObj["iespk"].get<std::string>();

        if(this->identity_->IESPublicKey() == ies_publicKey)
            return true;

        if(this->known_nodes_ies_.find(ies_publicKey) == this->known_nodes_ies_.end())
            return true;

        if(this->authenticated_nodes_ies_.find(ies_publicKey) != this->authenticated_nodes_ies_.end())
            return true;

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
            std::cout<<data.size()<<std::endl;
            if(!utils::checkParams(jsonObj,{"dsapk","iespk","data","signature","type"}))
                return false;
            
            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            if(this->identity_->IESPublicKey() == ies_publicKey)
                return true;

            //check if known node
            if(!(this->verifyPK(ies_publicKey,dsa_publicKey))){
                this->mlogger_->Error("Unknown public key");
                return true;
            }

            //verify sent data
            if (!this->identity_->VerifyData(dsa_publicKey,jsonObj["data"].get<std::string>(),jsonObj["signature"].get<std::string>())){
                this->mlogger_->Error("Verification failed...");
                return true;
            }

            switch(jsonObj["type"].get<int>()){
                case TX_BROADCAST: {
                    auto data = nlohmann::json::parse(jsonObj["data"].dump());

                    //TODO: Broadcast transactions to all authenticated nodes

                    if (!utils::checkParams(data, {"data", "signature", "pk"}))
                        return true;

                    //compute transaction hash
                    std::string tx_hash = this->identity_->ComputeHash(jsonObj["data"].get<std::string>());

                    if (!this->identity_->VerifyData(data["pk"].get<std::string>(),jsonObj["data"].get<std::string>(),jsonObj["signature"].get<std::string>())){
                        this->TransactionVote(tx_hash,ies_publicKey,-1);
                        this->mlogger_->Error("Verification failed...");
                        return true;
                    }

                    if(this->verified_transactions_.find(tx_hash) != this->verified_transactions_.end()){
                        //transaction exists: increase upvote
                        this->TransactionVote(tx_hash,ies_publicKey,1);
                    }else{
                        this->AddVerifiedTx(tx_hash,data["data"].get<std::string>());
                    }


                }
                    break;
                    // this->ReceiveTransaction();
                case BX_BROADCAST:
                    break;
                    // this->ReceiveBlock();
                case AUTH_CHALLENGE: {
                        this->mlogger_->Debug("CHALLENGE RECIEVED");
                        //received authentication challenge from alleged known node
                        try{
                            nlohmann::json parsed,response;
                            auto dat = jsonObj["data"].get<std::string>();
                            
                            auto plain = this->identity_->DecryptData(dat);
                            parsed = nlohmann::json::parse(plain);
                            
                            if(!utils::checkParams(parsed,{"challenge"}))
                                return true;
                            
                            response["data"]["solution"] = parsed["challenge"].get<std::string>();
                            std::cout<<response<<std::endl;
                            this->DirectMessage(ies_publicKey,response,AUTH_SOLUTION,[&](bool){
                                //success
                            });
                            

                        }catch(std::exception& e){
                            this->mlogger_->Error(e.what());
                            return true;
                        }            

                    }
                    break;
                    
                case AUTH_SOLUTION: {
                        this->mlogger_->Debug("SOLUTION RECIEVED:");
                        try{
                            nlohmann::json parsed;
                            auto dat = jsonObj["data"].get<std::string>();

                            auto plaint = this->identity_->DecryptData(dat);
                            std::cout<<"P:::"<<plaint<<std::endl;
                            std::cout<<dat<<std::endl;
                            parsed = nlohmann::json::parse(plaint);
                            std::cout<<parsed["solution"]<<std::endl;
                            if(!utils::checkParams(parsed,{"solution"}))
                                return true;
                            
                            if(!this->CheckSolution(ies_publicKey,parsed["solution"].get<std::string>())){
                                return true;
                            }
                            this->AuthNode(ies_publicKey);

                        }catch(std::exception& e){
                            this->mlogger_->Error(e.what());
                            return true;
                        }       
                        
                    }
                    break;

                default:
                    return true;
                
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
void Blockchain::AuthNode(const std::string& ies_pk){
    this->mlogger_->Info("Authenticated node: ",ies_pk);
    std::lock_guard<std::mutex> lck(this->mutex);
    this->authenticated_nodes_ies_[ies_pk] = 1;
    this->auth_solutions_.erase(ies_pk);
}

void Blockchain::AddKnownNode(const std::string& ies_pk,const std::string& dsa_pk){
    std::lock_guard<std::mutex> lck(this->mutex);

    this->known_nodes_ies_[ies_pk] = 1;
    this->known_nodes_dsa_[dsa_pk] = 1;
}

void Blockchain::AddKnownNodes(const std::string& path){
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

void Blockchain::AddChallenge(const std::string& ies_pk,const std::string& solution){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->auth_solutions_[ies_pk] = solution;
}


void Blockchain::DirectMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = type;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();


    auto d = payload.dump();
    this->dht_net_->Put(dest_ies_pk,payload.dump(),std::move(cb));
}

void Blockchain::Announce(const std::function<void(bool)>& cb){
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

bool Blockchain::CheckSolution(const std::string& ies_pk,const std::string& proposed){
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

void Blockchain::TransactionVote(const std::string& tx_hash,const std::string& pk,int vote){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->transaction_votes_[tx_hash][pk] = vote;
}

void Blockchain::AddVerifiedTx(const std::string& tx_hash,const std::string& data){
    //check if tx count >= BLOCK_NUM
    if(this->verified_transactions_.size() > BLOCK_MAX){
        //add existing txs to block
        this->CreateBlock();

    }
    //if so add to block
    std::lock_guard<std::mutex> lck(this->mutex);
    this->verified_transactions_[tx_hash] = data;
}

void Blockchain::CreateBlock() {
    //loop
    std::vector<std::string> tx_hashes,txs;
    for(auto& tx: this->verified_transactions_){
        tx_hashes.push_back(tx.first);
        txs.push_back(tx.second);
    }

    //compute merkle tree
    auto tree = MerkleNode::MerkleTree(tx_hashes);

    auto e_merkle = this->identity_->EncryptData(tree->Hash());

    Block block;
    block.block_header = e_merkle;
    block.merkle_root = tree->Hash();
    block.tx_hashes = tx_hashes;
    block.txs = this->verified_transactions_;
    using namespace std::chrono;
    milliseconds ms = duration_cast< milliseconds >(
            system_clock::now().time_since_epoch()
    );
    block.timestamp = ms.count();

    if(this->block_chain_.empty()){
        //create genesis block
        block.prev_block  = "";
        block.next_block = "";
        this->block_chain_.push_back(block);

    }else{
        //update hashes and append to block
        this->block_chain_.back().next_block = block.block_header;
        block.prev_block = this->block_chain_.back().block_header;

        this->block_chain_.push_back(block);

    }

    //delete previous txs and tx_votes
    for(auto& tx: this->verified_transactions_){
        this->verified_transactions_.erase(tx.first);
        this->transaction_votes_.erase(tx.first);
    }

    //broadcast block
    this->BroadcastBlock();

}


void Blockchain::BroadcastBlock(){
    //broadcast latest block
    nlohmann::json  data,tmp;
    auto block = this->block_chain_.back();
    block.to_json(data,block);
    data["data"] = tmp;

    for(auto& node: authenticated_nodes_ies_){
        this->DirectMessage(node.first,data,BX_BROADCAST,[&](bool){

        });
    }


}