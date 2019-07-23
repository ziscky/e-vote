//
// Created by emok on 7/22/19.
//

#include <utility>
#include "litechain.h"
#include "security/ecc.hpp"


void Litechain::InitializeAuthenticationChannels(){
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
void Litechain::InitializeInternalChannels(){
    this->dht_net_->InternalChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try{

            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());
            if(!this->VerifyMessage(jsonObj)){
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            switch(jsonObj["type"].get<int>()){
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

                        this->InternalMessage(ies_publicKey,response,AUTH_SOLUTION,[&](bool s){
                            //success
                            if(s)
                                this->mlogger_->Debug("Succesfully sent solution");
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
                        this->AuthNode(ies_publicKey);

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
                        this->mlogger_->Debug(plain);
                        parsed = nlohmann::json::parse(plain);


                        if (!utils::checkParams(parsed, {"height", "block_header"}))
                            return true;

                        this->mlogger_->Debug("Parsed:: data");

                        Block b;
                        b.height = parsed["height"].get<long>();
                        b.block_header = parsed["block_header"].get<std::string>();


                        this->ForkVote(b,ies_publicKey);
                        //check if 2/3 of network agrees
                        for(const auto& it: this->fork_votes_){
                            this->mlogger_->Debug("FORK resolved");
                            if(it.second.size() >= (0.6667 * this->authenticated_nodes_ies_.size())){
                                this->mlogger_->Debug("Blockchain fork consensus reached");


                            }
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

                        //retrieve requested block
//                        this->mlogger_->Debug(plain);
                        if (!utils::checkParams(parsed, {"height", "block_header", "merkle_root","tx_hashes"}))
                            return true;

                        this->mlogger_->Debug("Parsed:: data");

                        Block b;
                        b.height = parsed["height"].get<long>();
                        b.block_header = parsed["block_header"].get<std::string>();
                        b.merkle_root = parsed["merkle_root"].get<std::string>();
                        b.tx_hashes = parsed["tx_hashes"].get<std::vector<std::string>>();


                        this->CloseVote(b,ies_publicKey);
                        //check if 2/3 of network agrees
                        for(const auto& it: this->close_votes_){
                            this->mlogger_->Debug("CLOSURE resolved");
                            if(it.second.size() >= (0.6667 * this->authenticated_nodes_ies_.size())){
                                this->mlogger_->Debug("Blockchain closure consensus reached");


                            }
                        }


                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                case INIT_TX:
                    if(this->init_consensus_reached_){
                        break;
                    }
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
                        b.height = parsed["height"].get<long>();
                        b.block_header = parsed["block_header"].get<std::string>();
                        b.merkle_root = parsed["merkle_root"].get<std::string>();
                        b.tx_hashes = parsed["tx_hashes"].get<std::vector<std::string>>();

                        b.iespk = ies_publicKey;
                        this->InitVote(b,ies_publicKey);
                        //check if 2/3 of network agrees
                        for(const auto& it: this->init_votes_){

                            if(static_cast<float>(it.second.size()) >= (0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size()))){
                                this->mlogger_->Debug("CHAIN INIT resolved");
                                this->mlogger_->Debug("Blockchain init consensus reached");
                                this->init_consensus_reached_ = true;

                            }
                        }


                    }catch (std::exception& e){
                        this->mlogger_->Error(e.what());
                        return true;
                    }
                    break;
                case LITE_RX:
                    this->mlogger_->Debug("Received verified transaction");
                    try{
                        nlohmann::json parsed,response;
                        auto dat = jsonObj["data"].get<std::string>();

                        auto plain = this->identity_->DecryptData(dat);
                        parsed = nlohmann::json::parse(plain);


                        this->mlogger_->Debug(parsed["data"].get<std::string>());
//                        this->mlogger_->Debug();

                        if (!this->identity_->VerifyData(parsed["pk"].get<std::string>(),parsed["data"].get<std::string>(),parsed["signature"].get<std::string>())){
                            this->mlogger_->Error("TX verification failed!");
                            return true;
                        };
                        this->CacheTX(parsed["signature"].get<std::string>(), parsed["data"].get<std::string>(),
                                      !(parsed["chain"].get<std::string>() == "PARENT"));

                    }catch(std::exception& e){
                        this->mlogger_->Error(e.what());
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

}
void Litechain::InitializeExplorerChannels(){
    this->dht_net_->XPLRXChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool {
        try{
            auto jsonObj =  utils::msgPackToJson((const char*)data[0]->data.data(), data[0]->data.size());

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            this->mlogger_->Debug("XPLRX RECEIVED: ",ies_publicKey);

            nlohmann::json _parsed,response;
            auto dat = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(dat);
            _parsed = nlohmann::json::parse(plain);

//            this->mlogger_->Debug(_parsed);
            for(json::iterator parsed = _parsed.begin(); parsed != _parsed.end(); ++parsed){
                if (!utils::checkParams(*parsed, {"height", "block_header", "merkle_root","tx_hashes"}))
                    return true;

                this->mlogger_->Debug("Parsed:: data");

                Block b;
                b.height = (*parsed)["height"].get<long>();
                b.block_header = (*parsed)["block_header"].get<std::string>();
                b.merkle_root = (*parsed)["merkle_root"].get<std::string>();
                b.tx_hashes = (*parsed)["tx_hashes"].get<std::vector<std::string>>();
                b.txs = (*parsed)["transactions"].get<std::unordered_map<std::string,std::string>>();
                b.type = (*parsed)["type"].get<std::string>();
                b.prev_block = (*parsed)["prev_hash"].get<std::string>();
                b.next_block = (*parsed)["next_hash"].get<std::string>();

                this->BXRQVote(b,ies_publicKey);
//                this->mlogger_->Debug(this->block_rq_votes_[0].size());
                //check if 2/3 of network agrees
                for(const auto& height: this->block_rq_votes_){
                    for(const auto& votes: height.second){
                        if(static_cast<float>(votes.second.size()) >= 0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size())){
                            //2/3 of the network agrees on the block
                            this->StoreBlock(b);
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
void Litechain::InitializeIntegrationChannels(){
    this->dht_net_->TXRXChannel([&](const std::vector<std::shared_ptr<dht::Value>>& data)->bool{
        try {
            auto jsonObj = utils::msgPackToJson((const char *) data[0]->data.data(), data[0]->data.size());
            if (!this->VerifyMessage(jsonObj)) {
                return true;
            }

            auto dsa_publicKey = jsonObj["dsapk"].get<string>();
            auto ies_publicKey = jsonObj["iespk"].get<string>();

            this->mlogger_->Debug("TXRX RECEIVED: ", ies_publicKey);

            nlohmann::json _parsed, response;
            auto dat = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(dat);
            _parsed = nlohmann::json::parse(plain);

            //contains tx
            this->mlogger_->Debug(plain);
            this->CacheTX(_parsed["pk"].get<std::string>(), _parsed["data"].get<std::string>(),
                          !(_parsed["chain"].get<std::string>() == "PARENT"));

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

            nlohmann::json _parsed,response;
            auto dat = jsonObj["data"].get<std::string>();

            auto plain = this->identity_->DecryptData(dat);
            _parsed = nlohmann::json::parse(plain);

            this->mlogger_->Debug(_parsed);
            for(json::iterator parsed = _parsed.begin(); parsed != _parsed.end(); ++parsed){
                if (!utils::checkParams(*parsed, {"height", "block_header", "merkle_root","tx_hashes"}))
                    return true;

                this->mlogger_->Debug("Parsed:: data");

                Block b;
                b.height = (*parsed)["height"].get<long>();
                b.block_header = (*parsed)["block_header"].get<std::string>();
                b.merkle_root = (*parsed)["merkle_root"].get<std::string>();
                b.tx_hashes = (*parsed)["tx_hashes"].get<std::vector<std::string>>();
                b.txs = (*parsed)["transactions"].get<std::unordered_map<std::string,std::string>>();

                this->BXRQVote(b,ies_publicKey);
//                this->mlogger_->Debug(this->block_rq_votes_[0].size());
                //check if 2/3 of network agrees
                for(const auto& height: this->block_rq_votes_){
                    for(const auto& votes: height.second){
                        if(static_cast<float>(votes.second.size()) >= 0.6667 * static_cast<float>(this->authenticated_nodes_ies_.size())){
                            //2/3 of the network agrees on the block
                            this->StoreBlock(b);
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