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
    this->dht_net_->fork_channel_ = this->identity_->IESPublicKey()+std::to_string(FORK_BROADCAST);
    this->dht_net_->init_channel_ = this->identity_->IESPublicKey()+std::to_string(INIT_BROADCAST);
    this->dht_net_->close_channel_ = this->identity_->IESPublicKey()+std::to_string(CLOSE_BROADCAST);
    this->dht_net_->bxrq_channel_ = this->identity_->IESPublicKey()+std::to_string(BLOCK_RQ);
    this->dht_net_->bxrx_channel_ = this->identity_->IESPublicKey()+std::to_string(BLOCK_RX);
    this->dht_net_->Start();

    //announce startup to known nodes
    this->Announce([&](bool success){});
    //TODO: if blocks exist on disk , start workers
    //


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

        this->InternalMessage(ies_publicKey,payload,AUTH_CHALLENGE,[&](bool success){
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
            this->mlogger_->Debug(plain);


            if (!utils::checkParams(parsed, {"data", "signature", "pk"}))
                return true;

            if (!this->identity_->VerifyData(parsed["pk"].get<std::string>(),parsed["data"].get<std::string>(),parsed["signature"].get<std::string>())){
                //TODO: downvote node
                this->mlogger_->Error("Verification failed...");
                return true;
            }

            parsed["iespk"] = ies_publicKey;
            this->transaction_mem_q_.try_enqueue(parsed.dump());


        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
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

    this->dht_net_->ForkChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        //stop creation of blocks
        //compute sha256(blockheaders...) = fork_hash
        //broadcast fork_hash to all auth_nodes
        try {
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            nlohmann::json payload,parsed;

            Block b = this->block_chain_.back();
            b.to_json(parsed,b);
            this->ForkVote(b,this->identity_->IESPublicKey());

            payload["data"] = parsed;
            for(const auto& node: this->authenticated_nodes_ies_){
                this->InternalMessage(node.first,payload,FORK_TX,[](bool){});
            }

        }catch(std::exception e){

        }
        return true;
    });

    this->dht_net_->ChainInitChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        //receive the genesis block
        //perform consensus as normal
        //TODO: election candidate info.
        try {
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            //received chain initialization request
            this->mlogger_->Debug("CHAIN_INIT RECEIVED FROM: ", ies_publicKey);

            auto data = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(data);
            std::vector<string> txs{plain};
            auto block = this->CreateGenesis(txs);
            block.height  = 0;

            nlohmann::json payload,parsed;
            block.to_json(parsed,block);

            this->InitVote(block,this->identity_->IESPublicKey());

            payload["data"] = parsed;
            for(const auto& node: this->authenticated_nodes_ies_){
                this->mlogger_->Debug("Sending init",block.block_header);
                this->InternalMessage(node.first,payload,INIT_TX,[](bool){});
            }


        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        return true;
    });

    this->dht_net_->ChainCloseChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        //receive the genesis block
        //perform consensus as normal
        try {
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            //received fork initialization request
            //broadcast o
            this->mlogger_->Debug("CHAIN_CLOSE RECEIVED FROM: ", ies_publicKey);
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

            //check whether the fork is valid
            if(b.height < this->block_chain_.back().height){
                return true;
            }
            auto tree = MerkleNode::MerkleTree(b.tx_hashes);
            if(tree->Hash() != this->block_chain_.back().merkle_root){
                return true;
            }

            if(b.block_header != this->block_chain_.back().block_header){
                return true;
            }
            this->CloseVote(b,this->identity_->IESPublicKey());
            nlohmann::json payload;
            payload["data"] = parsed;
            for(const auto& node: this->authenticated_nodes_ies_){
                this->InternalMessage(node.first,payload,CLOSE_TX,[](bool){});
            }


        }catch(std::exception e){

        }
        return true;
    });




    this->dht_net_->BXRQChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        //receive types requests:
        ////get at a particular height
        //// get a range of heights
        ////specify from parent or fork
        try {
            auto jsonObj = utils::msgPackToJson((const char *) data[0]->data.data(), data[0]->size());
            if (!this->VerifyMessage(jsonObj)) {
                return true;
            }
            auto payload = jsonObj["data"].get<std::string>();
            auto iespk = jsonObj["iespk"].get<std::string>();
            auto dsapk = jsonObj["dsapk"].get<std::string>();

            auto parsed = nlohmann::json::parse(this->identity_->DecryptData(payload));

            std::string chain;
            if (utils::checkParams(parsed, {"height", "chain"})) {
                //retrieve block at that height
                chain = parsed["chain"].get<std::string>();
                int height = parsed["height"].get<int>();

                if (height > this->block_chain_.back().height) {
                    return true;
                }

                auto block = this->RetreiveBlock(height);
                nlohmann::json resp, data;
                block.to_json(data, block);

                resp["data"] = std::vector<nlohmann::json>{data};
                this->DirectMessage(iespk, resp, BLOCK_RX, [&](bool) {});
                return true;
            }

            if (utils::checkParams(parsed, {"rangeStart", "rangeEnd", "chain"})) {
                chain = parsed["chain"].get<std::string>();
                int start_height = parsed["rangeStart"].get<int>();
                int stop_height = parsed["rangeEnd"].get<int>();

                if ((start_height >= this->block_chain_.back().height) ||
                    (stop_height > this->block_chain_.back().height)) {
                    return true;
                }

                std::vector<nlohmann::json> filtered;
                for (int i = start_height; i <= stop_height; i++) {
                    nlohmann::json tmp;
                    auto block = this->RetreiveBlock(i);
                    block.to_json(tmp, block);
                    filtered.push_back(tmp);
                }

                nlohmann::json resp;
                resp["data"] = filtered;
                this->DirectMessage(iespk, resp, BLOCK_RX, [&](bool) {});
                return true;
            }

            if (utils::checkParams(parsed, {"genesis", "chain"})) {
                chain = parsed["chain"].get<std::string>();
                int height = 0;

                if (this->block_chain_.empty()) {
                    return true;
                }
                if (height > this->block_chain_.back().height) {
                    return true;
                }

                auto block = this->RetreiveBlock(height);
                nlohmann::json resp, data;
                block.to_json(data, block);

                resp["data"] = std::vector<nlohmann::json>{data};
                this->DirectMessage(iespk, resp, BLOCK_RX, [&](bool) {});
                return true;

            }

            if (utils::checkParams(parsed, {"death", "chain"})) {
                chain = parsed["chain"].get<std::string>();
                int height = this->block_chain_.back().height;

                if (this->block_chain_.empty()) {
                    return true;
                }


                auto block = this->RetreiveBlock(height);
                nlohmann::json resp, data;
                block.to_json(data, block);

                resp["data"] = std::vector<nlohmann::json>{data};
                this->DirectMessage(iespk, resp, BLOCK_RX, [&](bool) {});
                return true;
            }
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        return true;
    });

    this->dht_net_->BXRXChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            this->mlogger_->Debug("BXRX RECEIVED: ",ies_publicKey);

            nlohmann::json parsed,response;
            auto dat = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(dat);
            parsed = nlohmann::json::parse(plain);

            this->mlogger_->Debug(plain);

            for(json::iterator it = parsed.begin(); it != parsed.end(); ++it){
                nlohmann::json parsed = (*it);
                if(!utils::checkParams(parsed,{"height", "block_header", "merkle_root","tx_hashes"})){
                    return true;
                }
                Block b;
                b.height = parsed["height"].get<long>();
                b.block_header = parsed["block_header"].get<std::string>();
                b.merkle_root = parsed["merkle_root"].get<std::string>();
                b.tx_hashes = parsed["tx_hashes"].get<std::vector<std::string>>();
                b.txs = parsed["txs"].get<std::unordered_map<std::string,std::string>>();

                this->BXRQVote(b,ies_publicKey);
                //check if 2/3 of network agrees
                for(const auto& height: this->block_rq_votes_){
                    for(const auto& votes: height.second){
                        if(static_cast<float>(votes.second.size()) >= 0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size())){
                            //2/3 of the network agrees on the block
                            this->AddToChain(b,false);
                        }
                    }
                }
            }

        }catch (std::exception& e){
            this->mlogger_->Error(e.what());
            return true;
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
                case BX_VOTE_RQ:{
                    this->mlogger_->Debug("Block RQ RECEIVED: ",ies_publicKey);

                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        if(!utils::checkParams(parsed,{"height"}))
                            return true;
                        //retrieve requested block
                        if(parsed["height"].get<int>() > this->block_chain_.back().height){
                            return true;
                        }

                        Block block = this->block_chain_[parsed["height"].get<int>()];
                        nlohmann::json tmp;
                        block.to_json(tmp,block);

                        response["data"] = tmp;

                        this->DirectMessage(ies_publicKey,response,BX_BROADCAST,[&](bool){});
//                        this->broadcast_blocks_.try_enqueue()
                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                }
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

                            this->InternalMessage(ies_publicKey,response,AUTH_SOLUTION,[&](bool){
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
                case FORK_TX:{
                    this->mlogger_->Debug("Fork TX RECEIVED: ",ies_publicKey);
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        if(!utils::checkParams(parsed,{"height"}))
                            return true;

                        //retrieve requested block
                        if(parsed["height"].get<int>() > this->block_chain_.back().height){
                            return true;
                        }

                        Block block = this->block_chain_[parsed["height"].get<int>()];
                        this->ForkVote(block,ies_publicKey);
                        //check if 2/3 of network agrees
                        for(const auto& it: this->fork_votes_){
                            this->mlogger_->Debug("FORK resolved");
                            if(it.second.size() >= (0.6667 * this->authenticated_nodes_ies_.size())){
                                this->mlogger_->Debug("Blockchain fork consensus reached");

                                //close block chain and save to disk
                                //stop creation of blocks
                                this->block_worker_active_ = false;

                                //sign the stored block chain
                                std::string combined_headers;
                                for(const auto& block: this->block_chain_){
                                    combined_headers += block.block_header;
                                }
                                auto chain_hash = this->identity_->ComputeHash(combined_headers);
                                //TODO: SAVE BLOCKS TO DISK, FILENAME=CHAIN-HASH
                            }
                        }

                        std::vector<string> selected_nodes;
                        std::unordered_map<std::string,bool> voted_nodes;

                        std::for_each(this->fork_votes_.begin(),this->fork_votes_.end(),[&](const std::unordered_map<string,std::vector<string>>::value_type& votes){
                            for(const auto& it: votes.second){
                                voted_nodes[it] = true;
                            }
                        });

                        std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
                            if(voted_nodes.find(nodes.first) == voted_nodes.end()){
                                selected_nodes.push_back(nodes.first);
                            }
                        });
                        nlohmann::json payload;
                        payload["data"] = parsed;

                        for(const auto& it: selected_nodes){
                            this->InternalMessage(it,payload,FORK_TX,[](bool){});
                        }

                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                }
                case CLOSE_TX:
                    this->mlogger_->Debug("Close TX RECEIVED: ",ies_publicKey);
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        if(!utils::checkParams(parsed,{"height"}))
                            return true;

                        //retrieve requested block
                        if(parsed["height"].get<int>() > this->block_chain_.back().height){
                            return true;
                        }

                        Block block = this->block_chain_[parsed["height"].get<int>()];
                        this->CloseVote(block,ies_publicKey);
                        //check if 2/3 of network agrees
                        for(const auto& it: this->close_votes_){
                            this->mlogger_->Debug("CLOSURE resolved");
                            if(it.second.size() >= (0.6667 * this->authenticated_nodes_ies_.size())){
                                this->mlogger_->Debug("Blockchain fork consensus reached");

                                //close block chain and save to disk
                                //stop creation of blocks
                                this->block_worker_active_ = false;

                                //sign the stored block chain
                                std::string combined_headers;
                                for(const auto& block: this->block_chain_){
                                    combined_headers += block.block_header;
                                }
                                auto chain_hash = this->identity_->ComputeHash(combined_headers);
                                //TODO: SAVE BLOCKS TO DISK, FILENAME=CHAIN-HASH
                            }
                        }

                        std::vector<string> selected_nodes;
                        std::unordered_map<std::string,bool> voted_nodes;

                        std::for_each(this->fork_votes_.begin(),this->fork_votes_.end(),[&](const std::unordered_map<string,std::vector<string>>::value_type& votes){
                            for(const auto& it: votes.second){
                                voted_nodes[it] = true;
                            }
                        });

                        std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
                            if(voted_nodes.find(nodes.first) == voted_nodes.end()){
                                selected_nodes.push_back(nodes.first);
                            }
                        });
                        nlohmann::json payload;
                        payload["data"] = parsed;

                        for(const auto& it: selected_nodes){
                            this->InternalMessage(it,payload,CLOSE_TX,[](bool){});
                        }

                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                case INIT_TX:
                    this->mlogger_->Debug("Init TX RECEIVED: ",ies_publicKey);
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        this->mlogger_->Debug(plain);
                        if (!utils::checkParams(parsed, {"height", "block_header", "merkle_root","tx_hashes"}))
                            return true;

                        this->mlogger_->Debug("Parsed:: data");

                        Block b;
                        b.height = parsed["height"].get<int>();
                        b.block_header = parsed["block_header"].get<std::string>();
                        b.merkle_root = parsed["merkle_root"].get<std::string>();
                        b.tx_hashes = parsed["tx_hashes"].get<std::vector<std::string>>();
                        b.txs = parsed["transactions"].get<std::unordered_map<std::string,std::string>>();

                        b.iespk = ies_publicKey;
                        this->InitVote(b,ies_publicKey);
                        this->mlogger_->Debug("VOTED");
                        //check if 2/3 of network agrees
                        for(const auto& it: this->init_votes_){
                            this->mlogger_->Debug("CHAIN INIT resolved");
                            if(it.second.size() >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
                                this->mlogger_->Debug("Blockchain init consensus reached");

                                //close block chain and save to disk
                                //start accepting blockds and transactions

                                this->StartWorkers();

                                //add the genesis block to the chain
                                this->AddToChain(b,false);
                            }
                        }

                        std::vector<string> selected_nodes;
                        std::unordered_map<std::string,bool> voted_nodes;

                        std::for_each(this->init_votes_.begin(),this->init_votes_.end(),[&](const std::unordered_map<string,std::vector<string>>::value_type& votes){
                            for(const auto& it: votes.second){
                                voted_nodes[it] = true;
                            }
                        });

                        std::for_each(this->authenticated_nodes_ies_.begin(),this->authenticated_nodes_ies_.end(),[&](const std::unordered_map<std::string,int>::value_type& nodes){
                            if(voted_nodes.find(nodes.first) == voted_nodes.end()){
                                selected_nodes.push_back(nodes.first);
                            }
                        });
                        nlohmann::json payload;
                        this->mlogger_->Debug("loading json");
                        payload["data"] = parsed;
                        this->mlogger_->Debug("loaded");

                        for(const auto& it: selected_nodes){
                            this->InternalMessage(it,payload,INIT_TX,[](bool){});
                        }

                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                default:
                    return true;
                
            }
            
            this->mlogger_->Debug("Received msg on internal channel ",data[0]->data.size()," bytes");
            
        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        
        return true;
    });

    this->running_ = true;
    
}

void Blockchain::StartWorkers(){
    this->verifier_active_ = true;
    this->verification_worker_ = std::thread(&Blockchain::VerificationWorker,this);


    //start block worker threads
    this->block_worker_active_ = true;
    this->block_worker_ = std::thread(&Blockchain::BlockWorker,this);
    this->rx_block_worker_ = std::thread(&Blockchain::RXBlockWorker,this);
    this->bx_block_worker_ = std::thread(&Blockchain::BXBlockWorker,this);
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

Block& Blockchain::RetreiveBlock(int height){
    if(height < this->block_chain_.back().height){
        //TODO: load block from disk
    }
    return this->block_chain_.back();
}
void Blockchain::VerificationWorker() {

    //TODO: check if genesis block indicates current chain is a fork
    // verification includes checking whether keys are valid in the parent blockchain
    ////// -> load the block chain from disk
    ////// -> verify keys
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

        this->BlockVote(block,this->identity_->IESPublicKey());

        //add block to broadcast queue
        this->broadcast_blocks_.try_enqueue(block.block_header);

    }
}

void Blockchain::TransactionPurge(long timestamp){
    this->mlogger_->Debug("Removing older timestamps!");

    for(auto it = this->verified_tx_hash_mempool_.begin(); it != this->verified_tx_hash_mempool_.end();++it){
        auto transaction = nlohmann::json::parse(this->transaction_mempool_[*it]);

        if(transaction["timestamp"].get<long>() < timestamp){
            this->mlogger_->Error("Erasing TX: ",transaction["timestamp"]);
            this->verified_tx_hash_mempool_.erase(it);
            this->transaction_mempool_.erase(*it);
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

        //if received height is higher than my current vote
        //request for vote from unrecorded nodes
        if(!this->m_block_votes_.empty()){
            int current_vote_height = this->m_block_votes_.rbegin()->first;
            if(b.height > current_vote_height){
                //get nodes that haven't voted at height
                std::vector<std::string> selected;
                std::unordered_map<std::string,bool> voted;
                std::for_each(this->block_votes_[current_vote_height].begin(),this->block_votes_[current_vote_height].end(),[&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& votes){
                    std::for_each(votes.second.begin(),votes.second.end(),[&](std::string iespk){
                        voted[iespk] = true;
                    });
                });

                for(const auto& node: this->authenticated_nodes_ies_){
                    if(voted.find(node.first) == voted.end()){
                        selected.push_back(node.first);
                    }
                }

                nlohmann::json payload;
                payload["data"]["height"] = current_vote_height;
                for(const auto& node: selected){
                    this->InternalMessage(node,payload,BX_VOTE_RQ,[&](bool){});
                }


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

        this->BlockVote(b,b.iespk);
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
            this->AddToChain(this->proposed_block_mempool_[header],true);

            this->TransactionPurge(this->block_chain_.back().timestamp);

            //if accepted header was not our vote or we haven't voted yet
            if(m_vote != header){
                //reorganize blocks
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
            //get no. of votes
            int num_votes = 0;
            std::for_each(this->block_votes_[tmp].begin(),this->block_votes_[tmp].end(),[&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& votes){
                num_votes+=votes.second.size();
            });

            //check if no. of votes > 2/3 of authenticated nodes
            if(num_votes >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
                this->mlogger_->Error("NETWORK DEADLOCK DETECTED!!");
                //stop the formation of new blocks

                //get all transactions from diff. votes
                std::unordered_map<std::string,bool> transaction_map;
                std::vector<std::string> transactions;
                std::vector<std::string> transaction_hashes;
                std::for_each(this->block_votes_[tmp].begin(),this->block_votes_[tmp].end(),
                              [&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& vote){
                                  Block b = this->proposed_block_mempool_[vote.first];

                                  for(auto& tx: b.tx_hashes){
                                      if(transaction_map.find(tx) == transaction_map.end()){
                                          transactions.push_back(this->transaction_mempool_[tx]);
                                          transaction_map[tx] = true;
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

                std::transform(transactions.begin(),transactions.end(),std::back_inserter(transaction_hashes),[&](std::string tx) -> std::string{
                    return this->identity_->ComputeHash(tx);
                });

                Block b = this->CreateBlock(transaction_hashes,-1);
                this->TransactionPurge(nlohmann::json::parse(transactions.back())["timestamp"].get<long>());
                this->BlockVote(b,this->identity_->IESPublicKey());

                this->broadcast_blocks_.try_enqueue(b.block_header);



            }

    }

    }
}
void Blockchain::InitVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->init_votes_[b.block_header].push_back(iespk);
}

void Blockchain::CloseVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->close_votes_[b.block_header].push_back(iespk);
}

void Blockchain::ForkVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->fork_votes_[b.block_header].push_back(iespk);
}

void Blockchain::BlockVote(const Block& b,std::string iespk){
    std::lock_guard<std::mutex> lck(this->mutex);
    std::string prev_header;
    //remove previous vote
    std::for_each(this->block_votes_[b.height].begin(),this->block_votes_[b.height].end(),[&](const std::unordered_map<std::string,std::vector<std::string>>::value_type& vote){
        for(auto it = vote.second.begin();it != vote.second.end();++it){
            if(*it == iespk){
                this->proposed_block_mempool_.erase(b.block_header);
                this->block_votes_[b.height][vote.first].erase(it);
                prev_header = vote.first;
                it--;
            }
        }
    });

    this->block_votes_[b.height][b.block_header].push_back(iespk);
    this->proposed_block_mempool_[b.block_header] = b;
    if(iespk == this->identity_->IESPublicKey()){
        this->m_block_votes_[b.height] = b.block_header;
    }

    //remove previous vote
    if(!prev_header.empty()){
        if(this->block_votes_[b.height][prev_header].empty()){
            this->block_votes_[b.height].erase(prev_header);
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

void Blockchain::BXRQVote(const Block& b,const std::string& iespk){
    std::lock_guard<std::mutex> lck(this->fork_m);
    this->block_rq_votes_[b.height][b.block_header].push_back(iespk);
    this->block_rq_mem_[b.height][b.block_header] = b;
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

void Blockchain::InternalMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = type;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    std::string dst = dest_ies_pk;
    auto d = payload.dump();
    this->dht_net_->Put(dst,payload.dump(),std::move(cb));
}

void Blockchain::DirectMessage(const std::string& dest_ies_pk,nlohmann::json data,int type,std::function<void(bool)> cb){
    auto cipher = this->identity_->EncryptData(dest_ies_pk,data["data"].dump());
    auto signature = this->identity_->SignData(cipher);

    nlohmann:json payload;
    payload["data"] = cipher;
    payload["signature"] = signature;
    payload["type"] = -1;
    payload["iespk"] = this->identity_->IESPublicKey();
    payload["dsapk"] = this->identity_->DSAPublicKey();

    auto d = payload.dump();
    this->dht_net_->Put(dest_ies_pk+std::to_string(type),payload.dump(),std::move(cb));
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

Block Blockchain::CreateGenesis(std::vector<std::string>& txs){
    std::vector<std::string> tx_hashes;
    for(const auto& tx: txs){
        auto hash = this->identity_->ComputeHash(tx);
        tx_hashes.push_back(hash);
        this->transaction_mempool_[hash] = tx;
    }
    return this->CreateBlock(tx_hashes,0);
}

Block Blockchain::CreateBlock(std::vector<std::string>& txs,int init_height) {
    Block block;
    std::string last_tx;
    for (const auto &tx: txs) {
        block.tx_hashes.push_back(tx) ;
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
    if(init_height == 0){
        block.height = 0;
    }

    block.merkle_root = tree->Hash();

    //set block header to the sha256(merkle_root+height)
    block.block_header = this->identity_->ComputeHash(block.merkle_root+std::to_string(block.height));

    //set timestamp to last transaction in the block
    block.timestamp = nlohmann::json::parse(this->transaction_mempool_[last_tx])["timestamp"].get<long>();

    return block;
}


void Blockchain::AddToChain(Block block,bool fill){
    //fill in missing transactions
    if(fill) {
        for (auto &tx: block.tx_hashes) {
            if (this->transaction_mempool_.find(tx) == this->transaction_mempool_.end()) {
                //TODO: EDGE CASE
            }
            block.txs[tx] = this->transaction_mempool_[tx];

            this->transaction_votes_.erase(tx);
            this->sent_votes_.erase(tx);
        }
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

    block.timestamp = nlohmann::json::parse(block.txs[block.tx_hashes.back()])["timestamp"].get<long>();
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
        this->mlogger_->Info("\t","TX: ",this->transaction_mempool_[node.first]);
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
            this->mlogger_->Info("\t\t", "Header: ", vote.first," Votes: ",vote.second.size());
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
        this->mlogger_->Info("\t\t Timestamp: ",block.timestamp);
        this->mlogger_->Info("-------------------------- END BLOCK ------------------------------------","\n\n");
    }

}
