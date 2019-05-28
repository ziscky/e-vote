#include "blockchain.hpp"
#include "opendht.h"
#include "merkle.hpp"
#include <algorithm>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <string>
#include <utility>
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
    this->dht_net_->tx_channel_ = this->identity_->IESPublicKey()+std::to_string(TX_BROADCAST);
    this->dht_net_->block_channel_= this->identity_->IESPublicKey()+std::to_string(BX_BROADCAST);

    this->dht_net_->Start();

    //announce startup to known nodes
    this->Announce([&](bool success){});

    //start VerificationWorker thread
    this->verifier_active_ = true;
    this->verification_worker_ = std::thread(&Blockchain::VerificationWorker,this);


    //start block worker threads
    this->block_worker_active_ = true;
    this->block_worker_ = std::thread(&Blockchain::BlockWorker,this);
    this->rx_block_worker_ = std::thread(&Blockchain::RXBlockWorker,this);
    this->bx_block_worker_ = std::thread(&Blockchain::BXBlockWorker,this);

    //start sync tx thread
    this->sync_worker_active_ = true;
    this->sync_worker_  = std::thread(&Blockchain::SyncWorker,this);



    this->dht_net_->AnnounceChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
        if(!utils::checkParams(jsonObj,{"dsapk","iespk"}))
            return true;

        auto dsa_publicKey = jsonObj["dsapk"].get<string>();
        auto ies_publicKey = jsonObj["iespk"].get<string>();

        //check if we've sent a challenge already
        if(this->auth_solutions_.find(ies_publicKey) != this->auth_solutions_.end()){
            return true;
        }
        //TODO: GEN RANDOM CHALLENGE
        nlohmann::json payload;
        payload["data"]["challenge"] = "cipher";

        this->AddChallenge(ies_publicKey,"cipher");

        this->DirectMessage(ies_publicKey,payload,AUTH_CHALLENGE,[&](bool success){
            //success
            this->mlogger_->Debug("CHALLENGE SEND: ",success);
        });

        //re-announce for node to authenticate me
        if(this->authenticated_nodes_ies_.find(ies_publicKey) == this->authenticated_nodes_ies_.end())
            this->Announce(dsa_publicKey,[&](bool){});

        return true;
    });

    this->dht_net_->TXChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try {
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            this->mlogger_->Debug("Received TX Broadcast from: ",ies_publicKey);

            auto data = jsonObj["data"].get<std::string>();

            std::string plain = this->identity_->DecryptData(data);
            nlohmann::json parsed = nlohmann::json::parse(plain);
//            this->mlogger_->Debug();


            if (!utils::checkParams(parsed, {"data", "signature", "pk"}))
                return true;

            if (!this->identity_->VerifyData(parsed["pk"].get<std::string>(),parsed["data"].get<std::string>(),parsed["signature"].get<std::string>())){
                //TODO: downvote node
                this->mlogger_->Error("Verification failed...");
                return true;
            }

            parsed["iespk"] = ies_publicKey;
            this->transaction_mem_q_.try_enqueue(parsed.dump());


        }catch(std::exception e){

        }
        return true;
    });

    this->dht_net_->BXChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try {
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();
            //broadcast o
            this->mlogger_->Debug("BX_BROADCAST RECIEVED FROM: ", ies_publicKey);
            auto data = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(data);
            nlohmann::json parsed = nlohmann::json::parse(plain);

            this->mlogger_->Debug(plain);
            if (!utils::checkParams(parsed, {"height", "block_header", "merkle_root","tx_hashes"}))
                return true;

            this->mlogger_->Debug("Parsed:: data");

            Block b;
            b.height = parsed["height"].get<long>();
            b.block_header = parsed["block_header"].get<std::string>();
            b.merkle_root = parsed["merkle_root"].get<std::string>();
            b.tx_hashes = parsed["tx_hashes"].get<std::vector<std::string>>();

            b.iespk = ies_publicKey;
            this->received_blocks_.try_enqueue(b);

            //create block and add to block_queue_



        }catch(std::exception e){

        }
        return true;
    });
    this->dht_net_->InternalChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try{

            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            switch(jsonObj["type"].get<int>()){
                    // this->ReceiveTransaction();
                case AUTH_CHALLENGE: {
                        this->mlogger_->Debug("CHALLENGE RECIEVED FROM: ",ies_publicKey);
                        //received authentication challenge from alleged known node
                        try{
                            nlohmann::json parsed,response;
                            auto dat = jsonObj["data"].get<std::string>();
                            
                            auto plain = this->identity_->DecryptData(dat);
                            parsed = nlohmann::json::parse(plain);
                            
                            if(!utils::checkParams(parsed,{"challenge"}))
                                return true;
                            
                            response["data"]["solution"] = parsed["challenge"].get<std::string>();

                            this->DirectMessage(ies_publicKey,response,AUTH_SOLUTION,[&](bool){
                                //success
                            });
                            

                        }catch(std::exception& e){
                            this->mlogger_->Error(e.what());
                            return true;
                        }
                        break;
                    }

                    
                case AUTH_SOLUTION: {
                        this->mlogger_->Debug("SOLUTION RECIEVED FROM: ",ies_publicKey);
                        try{
                            nlohmann::json parsed;
                            auto dat = jsonObj["data"].get<std::string>();

                            auto plaint = this->identity_->DecryptData(dat);
                            parsed = nlohmann::json::parse(plaint);

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
                    break;
                    }

                default:
                    return true;
                
            }
            
            this->mlogger_->Debug("Received msg on internal channel ",data[0]->data.size()," bytes");
            
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        
        return true;
    });

    this->dht_net_->SyncChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            switch (jsonObj["type"].get<int>()){
                case SYNC_TX: {
                    //recieved request to sync w/ requester
                    break;
                }
                case SYNC_RX: {
                    break;

                }
            }


        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        return true;
    });

    this->running_ = true;
    
}

void Blockchain::SyncWorker(){
    this->mlogger_->Info("Started Sync Worker");
    while(this->sync_worker_active_){
        std::string transaction;
        this->sync_transaction_mem_q_.wait_dequeue(transaction);
        nlohmann::json parsed = nlohmann::json::parse(transaction);
        auto origin_iespk = parsed["iespk"].get<std::string>();

        parsed.erase("iespk");
        transaction = parsed.dump();

        //add iespk txs to storage
        this->sync_tx_votes_[origin_iespk].push_back(transaction);

        //check if sync_tx_votes >= 2/3 network
        if(this->sync_tx_votes_.size() >=  (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
            //TODO
            //prevent the creation of new blocks

            std::unordered_map<std::string,bool > selected_tx_hashes;
            std::vector<nlohmann::json> selected_txs;

            //consolidate all transactions
            for(auto& txs: this->sync_tx_votes_){
                for(auto& tx: txs.second) {
                    auto hash = this->identity_->ComputeHash(tx);
                    if (selected_tx_hashes.find(hash) == selected_tx_hashes.end()) {
                        selected_tx_hashes[hash] = true;
                        selected_txs.push_back(nlohmann::json::parse(tx));
                    }
                }
            }

            //sort transactions by timestamp
            std::sort(selected_txs.begin(),selected_txs.end(),[=](nlohmann::json& a,nlohmann::json& b)->bool{
               return a["timestamp"].get<long>() < b["timestamp"].get<long>();
            });

            //re-add transactions to verified queue.

            //erase all sync votes

        }
    }
}

void Blockchain::VerificationWorker() {
    this->mlogger_->Info("Started Verification Worker.");

    while(this->verifier_active_) {

        //if block_reorg consolidation is happening prevent block creation
        std::lock_guard<std::mutex> lck(this->block_reorg_);

        std::string transaction;
        this->transaction_mem_q_.wait_dequeue(transaction);

        nlohmann::json parsed = nlohmann::json::parse(transaction);
        auto origin_iespk = parsed["iespk"].get<std::string>();

        parsed.erase("iespk");
        transaction = parsed.dump();
        auto tx_hash = this->identity_->ComputeHash(transaction);

        if(!NewTX(tx_hash)){
            continue;
        }
        //check if transaction vote already exists exists
        if(this->transaction_votes_.find(tx_hash) != this->transaction_votes_.end()){
            bool exit = false;
            for(const auto& vote: this->transaction_votes_[tx_hash]){
                if(vote == origin_iespk){
                    //already received tx vote
                    exit =true;
                    break;
                }
            }
            if(exit)
                continue;
        }


        //store tx in mempool
        {
            std::lock_guard<std::mutex> lck(this->mutex);
            if(transaction.empty()){
                this->mlogger_->Error("EMPTY TX DETAILS! ",parsed);
            }
            this->transaction_mempool_[tx_hash] = transaction;
        }



        //add transaction vote
        this->TransactionVote(tx_hash,transaction,origin_iespk);

        //broadcast transactions
        nlohmann::json  payload;
        payload["data"] = parsed;

        //check if vote has already been sent to peer
        std::function<void(std::string)> tx_broadcast = [&](std::string iespk) {
            if (this->sent_votes_.find(tx_hash) != this->sent_votes_.end()) {
                if (this->sent_votes_[tx_hash].find(iespk) != this->sent_votes_[tx_hash].end()) {
                    return;
                }
            }
            this->DirectMessage(iespk, payload, TX_BROADCAST, [&](bool) {});

            //record sent vote
            std::lock_guard<std::mutex> lck(this->mutex);
            this->sent_votes_[tx_hash][iespk] = true;

        };

        for(auto& node: this->authenticated_nodes_ies_){
            tx_broadcast(node.first);
        }
    }
}

void Blockchain::BlockWorker() {
    while(this->block_worker_active_) {

        std::string transaction_hash;
        this->verified_transaction_q_.wait_dequeue(transaction_hash);

//        auto transaction = this->transaction_mempool_[transaction_hash];
        this->verified_tx_hash_mempool_.push_back(transaction_hash);

        bool sorted = false;

        if(!this->m_block_votes_.empty()){
            continue;
        }


        sort(this->verified_tx_hash_mempool_.begin(), this->verified_tx_hash_mempool_.end(),
             [&](std::string &a, std::string &b) -> bool {
                 nlohmann::json data1, data2;
                 data1 = nlohmann::json::parse(this->transaction_mempool_[a]);
                 data2 = nlohmann::json::parse(this->transaction_mempool_[b]);


                 return data1["timestamp"] < data2["timestamp"];
             });

        auto first_tx = nlohmann::json::parse(this->transaction_mempool_[this->verified_tx_hash_mempool_.front()]);
        auto last_tx = nlohmann::json::parse(this->transaction_mempool_[this->verified_tx_hash_mempool_.back()]);

        if((last_tx["timestamp"].get<long>() - first_tx["timestamp"].get<long>()) < 60000){
            continue;
        }
        this->mlogger_->Debug("BLOCK_TIME elapsed,creating block");

        long first = first_tx["timestamp"];
        std::vector<std::string> selected;
        for(auto it = this->verified_tx_hash_mempool_.begin();it != this->verified_tx_hash_mempool_.end();++it){
            auto obj = nlohmann::json::parse(this->transaction_mempool_[*it]);

            if((obj["timestamp"].get<long>() - first) <=60000){
                selected.push_back(*it);
                this->verified_tx_hash_mempool_.erase(it);
                it--;
            }

        }
        auto block = this->CreateBlock(selected,-1);

        //add block to proposed memqueue
        this->proposed_block_mempool_[block.block_header] = block;

        //increase block consensus vote
        this->block_votes_[block.height][block.block_header].push_back(this->identity_->IESPublicKey());
        this->m_block_votes_[block.height] = block.block_header;

        //add block to broadcast queue
        this->broadcast_blocks_.try_enqueue(block.block_header);

    }
}

void Blockchain::ProposedBlockReOrg(long timestamp){
    this->mlogger_->Debug("Removing older timestamps!");

    for(auto it = this->verified_tx_hash_mempool_.begin(); it != this->verified_tx_hash_mempool_.end();++it){
        auto transaction = nlohmann::json::parse(this->transaction_mempool_[*it]);

        if(transaction["timestamp"].get<long>() < timestamp){
            this->mlogger_->Error("Erasing TX: ",*it);
            this->verified_tx_hash_mempool_.erase(it);
            it--;
        }
    }

}

//all clean-up of containers is performed
void Blockchain::RXBlockWorker() {
    while(this->block_worker_active_) {
        Block b;
        this->received_blocks_.wait_dequeue(b);

        //if height <= chain height, discard
        if(!this->block_chain_.empty()) {
            if (b.height <= this->block_chain_.back().height) {
                this->mlogger_->Debug("Received Lagging Block -- Discarding");
                continue;
            }
        }

        if(b.merkle_root.empty() || b.tx_hashes.empty()){
            this->mlogger_->Error("Empty data from: ",b.iespk);
            continue;
        }
        //if tree hashes don't match, reject transaction
        auto tree = MerkleNode::MerkleTree(b.tx_hashes);
        if(this->identity_->ComputeHash(tree->Hash()+std::to_string(b.height)) != b.block_header){
            //TODO: downvote node
            this->mlogger_->Error("Block verification failed!");
            continue;
        }

        {
            std::lock_guard<std::mutex> lck(this->mutex);
            //TODO: check if iespk is switching votes
            this->block_votes_[b.height][b.block_header].push_back(b.iespk);
            this->proposed_block_mempool_[b.block_header] = b;
        }

        this->Consensus();

    }


}

void Blockchain::Consensus(){
    //get last height
    int height = 0;
    if(!this->block_chain_.empty()) {
        height = this->block_chain_.back().height + 1;
    }
    while((this->block_votes_.find(height) != this->block_votes_.end()) || this->block_chain_.empty()){
        if(this->block_chain_.empty()){
            if(height > 0){
                break;
            }
        }
        int tmp = height;
        height++;
        if(this->block_votes_[tmp].empty()){
            //erase
            this->block_votes_.erase(height);
            continue;
        }

        int votes = 0;
        std::string header;
        for (auto & it : this->block_votes_[tmp]) {
            if(it.second.size() >= votes){
                votes =  it.second.size();
                header = it.first;
            }
        }

        if ( votes >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))) {
            //get our vote at that height
            std::string m_vote = this->m_block_votes_[tmp];

            //2/3 votes achieved
            //add to chain
            this->AddToChain(this->proposed_block_mempool_[header]);

            //if accepted header was not our vote or we haven't voted yet
            if(m_vote != header){
                //reorganize blocks
                this->ProposedBlockReOrg(this->block_chain_.back().timestamp);
                this->proposed_block_mempool_.erase(m_vote);
            }

            {
                std::lock_guard<std::mutex> lck(this->mutex);
                this->block_votes_.erase(tmp);
                this->m_block_votes_.erase(tmp);
                this->proposed_block_mempool_.erase(header);

            }
        }else{
            //2/3 majority not yet achieved
            //check if no. of headers > 2/3 of authenticated nodes
            if(this->block_votes_[tmp].size() >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
                this->mlogger_->Error("NETWORK DEADLOCK DETECTED!!");
                //get all transactions from diff. votes
                std::unordered_map<std::string,bool> transaction_map;
                std::vector<std::string> transactions;
                std::vector<std::string> transaction_hashes;
                std::for_each(this->block_votes_[tmp].begin(),this->block_votes_[tmp].end(),
                              [&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& vote){
                                  Block b = this->proposed_block_mempool_[vote.first];

                                  for(auto& tx: b.txs){
                                      if(transaction_map.find(tx.first) == transaction_map.end()){
                                          transactions.push_back(tx.second);
                                          transaction_map[tx.first] = true;
                                      }
                                  }

                              });
                this->mlogger_->Debug("Consolidated Size: ",transactions.size());

                //reform only the deadlocked block
                std::sort(transactions.begin(),transactions.end(),[&](std::string& a,std::string& b){
                    auto parsed_a = nlohmann::json::parse(a);
                    auto parsed_b = nlohmann::json::parse(b);

                    return parsed_a["timestamp"] < parsed_b["timestamp"];
                });

                std::transform(transactions.begin(),transactions.end(),transaction_hashes.begin(),[&](std::string& tx) -> std::string{
                    return this->identity_->ComputeHash(tx);
                });

                Block b = this->CreateBlock(transaction_hashes,-1);

                //remove previous vote
                std::for_each(this->block_votes_[b.height].begin(),this->block_votes_[b.height].end(),[&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& vote){
                    for(auto it = vote.second.begin();it != vote.second.end();++it){
                        if(*it == this->identity_->IESPublicKey()){
                            this->proposed_block_mempool_.erase(b.block_header);
                            this->block_votes_[b.height][vote.first].erase(it);
                            it--;
                        }
                    }
                });

                this->block_votes_[b.height][b.block_header].push_back(this->identity_->IESPublicKey());
                this->proposed_block_mempool_[b.block_header] = b;

                this->broadcast_blocks_.try_enqueue(b.block_header);



            }

    }

    }
}
//
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

        if(ies == this->identity_->IESPublicKey()){
            continue;
        }
        this->AddKnownNode(ies,dsa);
    }
    
    
}

bool Blockchain::VerifyMessage(const nlohmann::json& jsonObj){
    if(!utils::checkParams(jsonObj,{"dsapk","iespk","data","signature","type"}))
        return false;

    auto dsa_publicKey = jsonObj["dsapk"].get<string>();
    auto ies_publicKey = jsonObj["iespk"].get<string>();

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

    return true;

}
void Blockchain::RequestBlocks(const std::string& iespk){
    nlohmann::json payload;
    payload["data"]["type"] = "RQ";
//    payload["data"]["last_header"] = this->last_agreed_block_header_;

    this->DirectMessage(iespk,payload,BX_UPDATE,[&](bool){});
}


std::vector<std::string> Blockchain::GetBlocksJSON(const std::string& from,const std::string& to){
    auto blocks = this->GetBlocks(from, to);

    std::vector<string> data;
    for(auto& block: blocks){
        nlohmann::json  j;
        block.to_json(j,block);
        data.push_back(j.dump());
    }
    return data;
}
std::vector<Block> Blockchain::GetBlocks(const std::string& from,const std::string& to){
    auto from_block = this->GetBlock(from);
    auto to_block = this->GetBlock(to);

    if(!from_block || !to_block){
        return std::vector<Block>();
    }

    std::vector<Block>::const_iterator from_iter,to_iter;
    from_iter = this->block_chain_.begin() + from_block->height;
    to_iter = this->block_chain_.begin() + 1 + to_block->height;

    return std::vector<Block>(from_iter,to_iter);
}


std::shared_ptr<Block> Blockchain::GetBlock(const std::string& hash){
    for(std::vector<Block>::const_reverse_iterator i = this->block_chain_.rbegin(); i != this->block_chain_.rend();++i){
        if((*i).block_header == hash){
            return std::make_shared<Block>(*i);
        }
    }
    return nullptr;
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

    std::string dst = dest_ies_pk;
    if(type == TX_BROADCAST || type == BX_BROADCAST || type == SYNC_TX){
        dst = dst + std::to_string(type);
    }

    auto d = payload.dump();
    this->dht_net_->Put(dst,payload.dump(),std::move(cb));
}

void Blockchain::Announce(const std::function<void(bool)>& cb){
    this->mlogger_->Debug("Announcing -> Startup");

    nlohmann::json payload;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    for(const auto& node: this->known_nodes_dsa_){
        this->mlogger_->Info("Announcing to: ",node.first);
        this->dht_net_->Put(node.first,payload.dump(),cb);
    }
    
}

void Blockchain::Announce(const std::string& dsapk,const std::function<void(bool)>& cb){
    this->mlogger_->Debug("Announcing -> Triggered");

    nlohmann::json payload;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();
    this->dht_net_->Put(dsapk,payload.dump(),cb);
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

void Blockchain::TransactionVote(const std::string& tx_hash,const std::string& tx,const std::string& pk){
    this->mlogger_->Debug("Increasing TX vote. ");
    {
        std::lock_guard<std::mutex> lck(this->mutex);
        this->transaction_votes_[tx_hash].push_back(pk);
    }
    this->mlogger_->Debug(static_cast<float>(this->transaction_votes_[tx_hash].size()),"<----->",(0.66667 * static_cast<float>(this->authenticated_nodes_ies_.size())));
    if(static_cast<float>(this->transaction_votes_[tx_hash].size()) >= (0.66667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
        //tx consensus enough
        this->verified_transaction_q_.try_enqueue(tx_hash);
    }
}


Block Blockchain::CreateBlock(std::vector<std::string>& txs,int init_height) {
    Block block;
    std::string last_tx;
    for (const auto &tx: txs) {
        block.tx_hashes.push_back(tx);
        block.txs[tx] = this->transaction_mempool_[tx];
        last_tx = tx;
    }

    //compute merkle tree
    auto tree = MerkleNode::MerkleTree(block.tx_hashes);

    if(init_height<0) {
        if (this->block_chain_.empty()) {
            block.height = 0;
        } else {
            block.height = this->block_chain_.back().height + 1;
        }
    }

    block.merkle_root = tree->Hash();

    //set block header to the sha256(merkle_root+height)
    block.block_header = this->identity_->ComputeHash(block.merkle_root+std::to_string(block.height));

    //set timestamp to last transaction in the block
    block.timestamp = nlohmann::json::parse(this->transaction_mempool_[last_tx])["timestamp"].get<long>();

    return block;
}


void Blockchain::AddToChain(Block block){
    //fill in missing transactions
    for(auto& tx: block.tx_hashes){
        if(this->transaction_mempool_.find(tx) == this->transaction_mempool_.end()){
            //TODO: EDGE CASE
        }
        block.txs[tx] = this->transaction_mempool_[tx];
        this->transaction_mempool_.erase(tx);
        this->transaction_votes_.erase(tx);
        this->sent_votes_.erase(tx);
    }

    if(this->block_chain_.empty()){
        this->mlogger_->Debug("Adding Genesis Block");
        //create genesis block
        block.prev_block  = "";
        block.next_block = "";

    }else{//update hashes and append to block
        this->block_chain_.back().next_block = block.block_header;
        block.prev_block = this->block_chain_.back().block_header;
    }
    this->block_chain_.push_back(block);
}

void Blockchain::BXBlockWorker(){

    while(this->block_worker_active_){

        std::string block_header;
        this->broadcast_blocks_.wait_dequeue(block_header);

        auto block = this->proposed_block_mempool_[block_header];

        //broadcast latest block
        nlohmann::json  data,tmp;
        block.to_json(tmp,block);

        data["data"] = tmp;

        for(const auto& node: authenticated_nodes_ies_){
            this->DirectMessage(node.first,data,BX_BROADCAST,[&](bool){

            });
        }
        this->mlogger_->Debug("Block broadcasted");
    }

}

bool Blockchain::NewTX(std::string hash){


    //check blocks from latest
    for(std::vector<Block>::const_reverse_iterator i = this->block_chain_.rbegin(); i != this->block_chain_.rend(); ++i ){
        for(const auto& tx: (*i).tx_hashes){
            if(tx == hash){
                return false;
            }
        }
    }

    return true;
}

bool Blockchain::NewBX(std::string hash,long height){
    //check if we are at same height

    //check blocks from latest
    for(std::vector<Block>::const_reverse_iterator i = this->block_chain_.rbegin(); i != this->block_chain_.rend(); ++i ){
       if(hash == i->merkle_root){
           return false;
       }
    }

    return true;
}


bool Blockchain::VerifyBlock(std::vector<std::string> tx_hashes,const std::string& merkle_root,const std::string& block_header,int height){

    auto tree = MerkleNode::MerkleTree(tx_hashes);
    //if tree hashes don't match, reject transaction

    if(tree->Hash() != merkle_root){
        return false;
    }

    return this->identity_->ComputeHash(merkle_root+std::to_string(height)) == block_header;


}


void Blockchain::BroadcastTransaction(){
    //demo tx
    std::lock_guard<std::mutex> lck(this->mutex);
    nlohmann::json data,payload;
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch());

    auto d = std::to_string(ms.count());
    data["data"] = d;
    auto sig = this->identity_->SignData(d);
    data["signature"] = sig;
    data["pk"] = this->identity_->DSAPublicKey();
    data["timestamp"] = ms.count();
    payload["data"] = data;


    this->mlogger_->Info("Broadcasting TX: ",payload.dump());
    for(auto& node: authenticated_nodes_ies_){
        this->DirectMessage(node.first,payload,TX_BROADCAST,[&](bool){

        });
    }

}

void Blockchain::PrintNodes(){
    this->mlogger_->Info("IESPK: ",this->identity_->IESPublicKey(),"\n");
    this->mlogger_->Info("Known Nodes: \n");
    for(auto& node: this->known_nodes_ies_){
        this->mlogger_->Info("\t",node.first);
    }

    this->mlogger_->Info("\nAuthed Nodes: \n");
    for(auto& node: this->authenticated_nodes_ies_){
        this->mlogger_->Info("\t",node.first);
    }

}

void Blockchain::PrintTX(){
    this->mlogger_->Info("IESPK: ",this->identity_->IESPublicKey(),"\n");
    this->mlogger_->Info("Verified tx: \n",this->verified_transaction_q_.size_approx());

    this->mlogger_->Info("TX Votes: \n");
    for(auto& node: this->transaction_votes_){
        this->mlogger_->Info("\t","TX: ",node.first);
        for(auto& votes: node.second){
            this->mlogger_->Info("\t\t",votes);
        }
    }

    this->mlogger_->Info("Sent Votes: ");
    for(auto& node: this->sent_votes_){
        this->mlogger_->Info("\t","TX: ",node.first);
    }

    this->mlogger_->Info("Block Votes: ");
    for(auto& node: this->block_votes_){
        this->mlogger_->Info("\t","Height: ",node.first);
        for(auto& vote: node.second) {
            this->mlogger_->Info("\t\t", "Header: ", vote.first);
        }
    }

}


void Blockchain::PrintBlocks() {
    this->mlogger_->Info("IESPK: ",this->identity_->IESPublicKey(),"\n");
    this->mlogger_->Info("BLOCKCHAIN: \n");
    int i = 0;
    for(const auto& block: this->block_chain_){
        i++;
        this->mlogger_->Info("-------------------------- BLOCK ",i,"------------------------------------");
        this->mlogger_->Info("\t\t Height: ",block.height);
        this->mlogger_->Info("\t\t Header: ",block.block_header);
        this->mlogger_->Info("\t\t prev_hash: ",block.prev_block);
        this->mlogger_->Info("\t\t next_hash: ",block.next_block);
        this->mlogger_->Info("\t\t Merkle root: ",block.merkle_root);
        this->mlogger_->Info("\t\t Transactions: ");
        for(const auto& tx: block.txs){
            this->mlogger_->Info("\t\t\t",tx.second);
        }
        this->mlogger_->Info("\t\t Num TX-CONTENT: ",block.txs.size());
        this->mlogger_->Info("-------------------------- END BLOCK ------------------------------------","\n\n");
    }

}
