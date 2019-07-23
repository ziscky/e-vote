//
// Created by emok on 7/22/19.
//
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


void Blockchain::InitializeInternalChannels(){
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

                case R_AUTH_CHALLENGE: {
                    this->mlogger_->Debug("R_CHALLENGE RECIEVED FROM: ",ies_publicKey);
                    //received authentication challenge from alleged known node
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        if(!utils::checkParams(parsed,{"challenge"}))
                            return true;

                        response["data"]["solution"] = parsed["challenge"].get<std::string>();

                        this->InternalMessage(ies_publicKey,response,R_AUTH_SOLUTION,[&](bool){
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
                        nlohmann::json payload;
                        payload["iespk"] = this->identity_->IESPublicKey();
                        payload["dsapk"] = this->identity_->DSAPublicKey();

                        this->DirectMessage(ies_publicKey,payload,R_ANNOUNCE,[](bool){});
                        this->AuthNode(ies_publicKey);

                    }catch(std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                }
                case R_AUTH_SOLUTION:
                    this->mlogger_->Debug("R_SOLUTION RECIEVED FROM: ",ies_publicKey);
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

                        //reauth with unknown nodes

                        this->AuthNode(ies_publicKey);

                        //get unauthed nodes
                        for(const auto& node: this->known_nodes_ies_){
                            if(this->authenticated_nodes_ies_.find(node.first) == this->authenticated_nodes_ies_.end()){
                                nlohmann::json payload;
                                payload["iespk"] = this->identity_->IESPublicKey();
                                payload["dsapk"] = this->identity_->DSAPublicKey();

                                this->DirectMessage(node.first,payload,R_ANNOUNCE,[](bool){});
                            }
                        }

                    }catch(std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                case FORK_TX:{
                    this->mlogger_->Debug("Fork TX RECEIVED: ",ies_publicKey);
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);

                        if(this->fork_consensus_reached_){
                            return true;
                        }
                        if(!utils::checkParams(parsed,{"height"}))
                            return true;

                        //retrieve requested block
                        if(parsed["height"].get<int>() > this->block_chain_.back().height){
                            return true;
                        }

                        Block block = this->block_chain_[parsed["height"].get<int>()];
                        this->ForkVote(block,ies_publicKey);
                        //check if 2/3 of network agrees
                        auto fork_threshold = static_cast<float>(this->authenticated_nodes_ies_.size() - this->getLiteNodes().size());
                        for(const auto& it: this->fork_votes_){


                            if(static_cast<float>(it.second.size()) >= (0.6667 * fork_threshold)){
                                this->mlogger_->Debug("FORK resolved");
                                this->mlogger_->Debug("Blockchain fork consensus reached");

                                this->fork_consensus_reached_ = true;
                                //close block chain and save to disk
                                //stop creation of blocks
//                                this->block_worker_active_ = false;

                                //sign the stored block chain
                                std::string combined_headers;
                                std::vector<std::string> txs;
                                for(const auto& block: this->block_chain_){
                                    combined_headers += block.block_header;
                                    txs.push_back(block.block_header);
                                }

                                auto chain_hash = this->identity_->ComputeHash(combined_headers);
                                this->mlogger_->Debug("CHAIN HASH:",chain_hash);
                                auto fork_block = this->CreateFork(txs,this->block_chain_.back().height);

                                this->mlogger_->Debug(fork_block.height,this->block_chain_.back().height);
                                fork_block.height = this->block_chain_.back().height + 1;
                                this->AddToChain(fork_block,false);



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

//                        this->mlogger_->Debug(plain);
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
                            if(static_cast<float>(it.second.size()) >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
                                if(this->init_consensus_reached_){
                                    break;
                                }
                                this->mlogger_->Debug("CHAIN INIT resolved");
                                this->mlogger_->Debug("Blockchain init consensus reached");

                                //close block chain and save to disk
                                //start accepting blockds and transactions

                                this->StartWorkers();
                                this->init_consensus_reached_ = true;

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
}
void Blockchain::InitializeLiteChannels(){
    this->dht_net_->TXRQChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool {
        try {
            auto jsonObj = utils::msgPackToJson((const char *) data[0]->data.data(), data[0]->data.size());
            if (!this->VerifyMessage(jsonObj)) {
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            this->mlogger_->Debug("Received TXRQ from: ", ies_publicKey);

            auto data = jsonObj["data"].get<std::string>();

            std::string plain = this->identity_->DecryptData(data);
            nlohmann::json parsed = nlohmann::json::parse(plain);
//            this->mlogger_->Debug(plain);

            if (!utils::checkParams(parsed, {"pk","chain"}))
                return true;

            //search for transaction
            auto pk = parsed["pk"].get<std::string>();
            auto chain = parsed["chain"].get<std::string>();

            if(chain == "PARENT"){
                auto tx = this->CheckParentExistence(pk);
                nlohmann::json parsed;

                if(tx == ""){
                    parsed["data"] = "ERROR";
                }else{
                    parsed["data"] = nlohmann::json::parse(tx);
                }

                this->DirectMessage(ies_publicKey,parsed,TRANSACTION_RX,[](bool){});
                return true;
            }
            auto tx = this->CheckForkExistence(pk);
            nlohmann::json p;

            if(tx == ""){
                p["data"] = "ERROR";
            }else{
                p["data"] = nlohmann::json::parse(tx);
            }
            this->DirectMessage(ies_publicKey,p,TRANSACTION_RX,[](bool){});
            return true;

        } catch (std::exception &e) {
            this->mlogger_->Error(e.what());
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

            if(this->fork_height > 0){
                return true;
            }

            this->ForkInitVote(this->identity_->IESPublicKey());

            if(this->fork_init_votes_ >= static_cast<int>(this->getLiteNodes().size())){
                this->mlogger_->Debug("Beginning Fork");
                parsed["height"] = this->block_chain_.back().height;
                parsed["block_header"] = this->block_chain_.back().block_header;
                payload["data"] = parsed;

                for(const auto& node: this->authenticated_nodes_ies_){
                    this->InternalMessage(node.first,payload,FORK_TX,[](bool){});
                }
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
                this->InternalMessage(node.first,payload,INIT_TX,[&](bool){
                    this->mlogger_->Debug("Succesfully Sent INIT");
                });
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

//            this->mlogger_->Debug(plain);
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
}
void Blockchain::InitializeExplorerChannels() {
    //support for block explorers, request for blocks without authentication
    this->dht_net_->XPLRQChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool {
        try{
            auto jsonObj = utils::msgPackToJson((const char *) data[0]->data.data(), data[0]->data.size());
            std::cout<<jsonObj<<std::endl;

            auto data = jsonObj["data"].get<std::string>();
            std::string plain = this->identity_->DecryptData(data);

            this->mlogger_->Debug(plain);
            nlohmann::json parsed = nlohmann::json::parse(plain);

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            std::string chain;
            if (utils::checkParams(parsed, {"height","chain"})) {
                //retrieve block at that height
                chain = parsed["chain"].get<std::string>();
                int height = parsed["height"].get<int>();

                if(this->block_chain_.empty()){
                    return true;
                }

                if (height > this->block_chain_.back().height) {
                    return true;
                }

                std::vector<nlohmann::json> parsed_blocks;
                nlohmann::json tmp;

                if(height == this->block_chain_.back().height){
                    auto block = this->block_chain_.back();
                    block.to_json(tmp,block);
                    parsed_blocks.push_back(tmp);
                }else{
                    for (int i = height; i <= this->block_chain_.back().height; i++) {
                        auto block = this->RetreiveBlock(i,chain);
                        block.to_json(tmp, block);
                        parsed_blocks.push_back(tmp);
                    }
                }

                nlohmann::json resp;
                resp["data"] = parsed_blocks;
                this->DirectMessage(ies_publicKey, resp, XPLR_RX, [&](bool) {});
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
                    auto block = this->RetreiveBlock(i,chain);
                    block.to_json(tmp, block);
                    filtered.push_back(tmp);
                }

                nlohmann::json resp;
                resp["data"] = filtered;
                this->DirectMessage(ies_publicKey, resp, XPLR_RX, [&](bool) {});
                return true;
            }

        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
        }
        return true;

    });


}

void Blockchain::InitializeAuthChannels() {
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

        return true;
    });
    this->dht_net_->ReactAnnounceChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
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

        this->InternalMessage(ies_publicKey,payload,R_AUTH_CHALLENGE,[&](bool success){
            //success
            this->mlogger_->Debug("CHALLENGE SEND: ",success);
        });
        return true;
    });
}

void Blockchain::InitializeConsensusChannels(){
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
//            this->mlogger_->Debug(plain);


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

//            this->mlogger_->Debug(plain);
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

        }catch(std::exception& e){
            this->mlogger_->Error(e.what());
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

                if(this->block_chain_.empty()){
                    return true;
                }
                if (height > this->block_chain_.back().height) {
                    return true;
                }

                auto block = this->RetreiveBlock(height,chain);
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
                    auto block = this->RetreiveBlock(i,chain);
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

                auto block = this->RetreiveBlock(height,chain);
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


                auto block = this->RetreiveBlock(height,chain);
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

//            this->mlogger_->Debug(plain);

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
}
