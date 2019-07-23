//
// Created by emok on 5/21/19.
//

#include <utility>
#include "litechain.h"
#include "security/ecc.hpp"

std::string Litechain::DHTRoutingTable(){
    return this->dht_net_->RoutingTable();
}

void Litechain::InitChain(const std::string& data) {
    this->mlogger_->Debug("Initializing Chain");
    nlohmann::json tmp= nlohmann::json::parse(data);
    this->mlogger_->Debug("Payload parsed");
    nlohmann::json payload;
    payload["data"] = tmp;
    this->mlogger_->Debug("Payload parsed");
    std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->mlogger_->Debug("Sending to",nodes.first);
        this->DirectMessage(nodes.first,payload,INIT_BROADCAST,[](bool){});
    });
}

void Litechain::InitFork() {
    nlohmann::json payload,data;
    payload["data"] = data;
    std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->DirectMessage(nodes.first,payload,FORK_BROADCAST,[](bool){});
    });

}

void Litechain::CloseChain() {
    nlohmann::json payload,data;
    payload["data"] = data;
    std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->DirectMessage(nodes.first,payload,CLOSE_BROADCAST,[](bool){});
    });
}

std::string Litechain::SeedKeys(const string& seed,bool deterministic){
    KeyGen<HexKeyPair> keygen(deterministic);
    auto keys = keygen.GenerateKeys(seed);
//    this->identity_ = std::make_shared<Identity>(keys.public_key,keys.private_key,keys.e_public_key,keys.e_private_key);
    nlohmann::json creds;
    creds["private_key"] = keys.private_key;
    creds["public_key"] = keys.public_key;
    creds["e_private_key"] = keys.e_private_key;
    creds["e_public_key"] = keys.e_public_key;

    return creds.dump();
}
void Litechain::BroadcastTX(const string& tx) {
    std::lock_guard<std::mutex> lck(this->mutex);
    nlohmann::json data,payload,tmp;
    tmp = nlohmann::json::parse(tx);
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch());

    auto d = std::to_string(ms.count());
    data["data"] = tx;
    auto sig = this->identity_->SignData(tx);
    data["signature"] = sig;
    data["pk"] = this->identity_->DSAPublicKey();
    data["timestamp"] = ms.count();
    payload["data"] = data;

    this->mlogger_->Info("Broadcasting TX: ",data["signature"]);
    for(auto& node: authenticated_nodes_ies_){
        this->DirectMessage(node.first,payload,TX_BROADCAST,[&](bool){

        });
    }

}
void Litechain::BlockRQ(nlohmann::json data) {
    nlohmann::json payload;
    payload["data"] = std::move(data);
    std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->DirectMessage(nodes.first,payload,BLOCK_RQ,[](bool){});
    });
}
void Litechain::ExplorerBlockRQ(nlohmann::json data) {
    nlohmann::json payload;
    payload["data"] = std::move(data);
    std::for_each(this->known_nodes_ies_.begin(),this->known_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->DirectMessage(nodes.first,payload,XPLR_RQ,[](bool){});
    });
}

void Litechain::Start(bool explorer) {
    this->dht_net_->announce_channel_ = this->identity_->DSAPublicKey();
    this->dht_net_->internal_channel_ = this->identity_->IESPublicKey();
    this->dht_net_->react_announce_channel_ = this->identity_->IESPublicKey() +std::to_string(R_ANNOUNCE);
    this->dht_net_->tx_channel_ = this->identity_->IESPublicKey()+std::to_string(TX_BROADCAST);
    this->dht_net_->block_channel_= this->identity_->IESPublicKey()+std::to_string(BX_BROADCAST);
    this->dht_net_->fork_channel_ = this->identity_->IESPublicKey()+std::to_string(FORK_BROADCAST);
    this->dht_net_->init_channel_ = this->identity_->IESPublicKey()+std::to_string(INIT_BROADCAST);
    this->dht_net_->close_channel_ = this->identity_->IESPublicKey()+std::to_string(CLOSE_BROADCAST);
    this->dht_net_->bxrq_channel_ = this->identity_->IESPublicKey()+std::to_string(BLOCK_RQ);
    this->dht_net_->bxrx_channel_ = this->identity_->IESPublicKey()+std::to_string(BLOCK_RX);
    this->dht_net_->txrx_channel_ = this->identity_->IESPublicKey()+std::to_string(TRANSACTION_RX);
    this->dht_net_->xplr_channel_ = this->identity_->IESPublicKey()+std::to_string(XPLR_RQ);
    this->dht_net_->xplrx_channel_ = this->identity_->IESPublicKey()+std::to_string(XPLR_RX);
    this->dht_net_->Start();
    this->Announce([&](bool success){});

    if(explorer){
        this->InitializeExplorerChannels();
        this->mlogger_->Info("Explorer Mode");
    }else{
        this->InitializeInternalChannels();
        this->InitializeAuthenticationChannels();
        this->InitializeIntegrationChannels();
        this->mlogger_->Info("Litenode mode");
    }

    this->running = true;
}

void Litechain::AddKnownNode(const std::string& ies_pk,const std::string& dsa_pk){
    std::lock_guard<std::mutex> lck(this->mutex);

    this->known_nodes_ies_[ies_pk] = 1;
    this->known_nodes_dsa_[dsa_pk] = 1;
    this->authenticated_nodes_ies_[ies_pk] = 1;
}

void Litechain::AddKnownNodes(const std::string& path){
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

void Litechain::StoreBlock(Block b){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->block_mempool_[b.height] = b;
}

std::string Litechain::GetBlock(int height,std::string chain,bool explorer){
    if(this->block_mempool_.find(height) == this->block_mempool_.end()){
        nlohmann::json payload;
        payload["height"] = height;
        payload["chain"] = chain;
        if(explorer){
            if(!this->block_mempool_.empty()) {
                payload["height"] = (--this->block_mempool_.end())->first;
                this->mlogger_->Debug("EXPLORING FROM:", payload["height"].get<int>());
            }else{
                payload["height"] = 0;
                this->mlogger_->Debug("EXPLORING FROM GENESIS");
            }
            this->ExplorerBlockRQ(payload);
            return "";
        }
        this->BlockRQ(payload);
        return "";
    }

    Block b = this->block_mempool_[height];
    nlohmann::json parsed;
    b.to_json(parsed,b);
    return parsed.dump();
}

void Litechain::DirectMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = type;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    std::string dst = dest_ies_pk;
    if(type >= 0){
        dst = dst + std::to_string(type);
    }

    auto d = payload.dump();
    this->dht_net_->Put(dst,payload.dump(),std::move(cb));
}

bool Litechain::CheckSolution(const std::string& ies_pk,const std::string& proposed){
    if(this->auth_solutions_.find(ies_pk) == this->auth_solutions_.end())
        return false;

    return this->auth_solutions_[ies_pk] == proposed;
}

void Litechain::AuthNode(const std::string& ies_pk){
    this->mlogger_->Info("Authenticated node: ",ies_pk);
    std::lock_guard<std::mutex> lck(this->mutex);
    this->authenticated_nodes_ies_[ies_pk] = 1;
    this->auth_solutions_.erase(ies_pk);
}
bool Litechain::VerifyMessage(const nlohmann::json& jsonObj){
    if(!utils::checkParams(jsonObj,{"dsapk","iespk","data","signature","type"}))
        return false;

    auto dsa_publicKey = jsonObj["dsapk"].get<string>();
    auto ies_publicKey = jsonObj["iespk"].get<string>();

    if(this->identity_->IESPublicKey() == ies_publicKey)
        return false;

//    if(!(jsonObj["type"].get<int>() == AUTH_CHALLENGE || jsonObj["type"].get<int>() == AUTH_SOLUTION)){
//        //clear auth solutions for iespk as auth has already been proved
//        this->auth_solutions_.erase(ies_publicKey);
//    }
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

bool Litechain::verifyPK(const string& ies_publicKey,const string& dsa_publicKey){
    return (this->known_nodes_ies_.find(ies_publicKey) != this->known_nodes_ies_.end()) && (this->known_nodes_dsa_.find(dsa_publicKey) != this->known_nodes_dsa_.end());
}


void Litechain::Announce(const std::string& dsapk,const std::function<void(bool)>& cb){
    this->mlogger_->Debug("Announcing -> Triggered");

    nlohmann::json payload;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();
    this->dht_net_->Put(dsapk,payload.dump(),cb);
}

void Litechain::AddChallenge(const std::string& ies_pk,const std::string& solution){
    std::lock_guard<std::mutex> lck(this->mutex);
    this->auth_solutions_[ies_pk] = solution;
}

void Litechain::ForkVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->fork_votes_[b.block_header].push_back(iespk);
}

void Litechain::BXRQVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->block_rq_votes_[b.height][b.block_header].push_back(iespk);
    this->block_rq_mem_[b.height][b.block_header] = b;
}


void Litechain::InitVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    if(!utils::vectorExists(this->init_votes_[b.block_header],iespk)){
        this->init_votes_[b.block_header].push_back(iespk);
    }
}

void Litechain::CloseVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->close_votes_[b.block_header].push_back(iespk);
}


void Litechain::InternalMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = type;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    const std::string& dst = dest_ies_pk;
    auto d = payload.dump();
    this->dht_net_->Put(dst,payload.dump(),std::move(cb));
}

void Litechain::Announce(const std::function<void(bool)>& cb){
    this->mlogger_->Debug("Announcing -> Startup");

    nlohmann::json payload;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    for(const auto& node: this->known_nodes_dsa_){
        this->mlogger_->Info("Announcing to: ",node.first);
        this->dht_net_->Put(node.first,payload.dump(),cb);
    }

}

void Litechain::CacheTX(const std::string& hash,const std::string& tx,bool fork){
    std::lock_guard<std::mutex> lck(this->mutex);
    if(fork){
        this->mlogger_->Debug("Detected Fork --> LITE");
        this->fork_transaction_mem_[hash] = tx;
        return;
    }
    this->transaction_mem_[hash] = tx;

}

std::string Litechain::GetTransactions(){
    std::vector<std::string> transactions;
    for(const auto& tx: this->transaction_mem_){
        transactions.push_back(tx.second);
    }

    nlohmann::json payload;
    payload["transactions"] = transactions;
    return payload.dump();

}

std::string Litechain::GetTransaction(std::string pubkey,std::string chain){
    if(chain == "FORK"){
        if(this->fork_transaction_mem_.find(pubkey) == this->fork_transaction_mem_.end()){
            this->RequestTransaction(pubkey,chain);
            return "";
        } else{
            nlohmann::json payload;
            payload["transaction"] = this->fork_transaction_mem_[pubkey];
            return payload.dump();
        }
    }
    if(this->transaction_mem_.find(pubkey) == this->transaction_mem_.end()){
        this->RequestTransaction(pubkey,chain);
        return "";
    }
    nlohmann::json payload;
    payload["transaction"] = this->transaction_mem_[pubkey];
    return payload.dump();

}

void Litechain::RequestTransaction(std::string pubkey, std::string chain){
    nlohmann::json payload,data;
    data["pk"] = pubkey;
    data["chain"] = chain;
    payload["data"] = data;
    std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
        this->DirectMessage(nodes.first,payload,TRANSACTION_RQ,[](bool){});
    });


}