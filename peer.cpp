#include <iostream>
#include <fstream>
#include <string>
#include <opendht.h>

#include <chrono>
#include <readline/readline.h>
#include <readline/history.h>
#include "blockchain/blockchain.hpp"

void asciiPrint();
void printHelp();

int main(int argc,char **argv){
    if(argc < 2){
        std::cerr<<"Format: ./binary /path/to/conf/file"<<std::endl;
        std::cout<<"Run {./binary generate} to generate config file "<<std::endl;
        return -1;
    }
    
    NodeConf conf;
    std::cout<<argv[1]<<std::endl;
    try{
        std::string arg = argv[1];
        if(arg == "generate"){
            json c;
            c["DHT_INTERNAL"] = "";
            c["DHT_VERIFIED"] = "";
            c["DHT_UNVERIFIED"] = "";
            c["DHT_ANNOUNCEMENT"] = "";
            c["DHT_BLOCK"] = "";
            c["MAINNET"] = false;
            c["MAINNET_ADDR"] = "";
            c["TESTNET_ADDR"] = "";
            c["PORT"] = "";
            c["NODE_ID"] = "";
            std::ofstream out("conf.json");
            out<<std::setw(4)<<c;
            out.close();
            return 0;
        }
        if(argc<3){
            std::cerr<<"Provide path to keyfile"<<std::endl;
            return -1;
        }
        std::ifstream conf_file(argv[1]);
        json parsed;
        conf_file >> parsed;

        conf.internal_channel = parsed["DHT_INTERNAL"];
        conf.verified_channel = parsed["DHT_VERIFIED"];
        conf.unverified_channel = parsed["DHT_UNVERIFIED"];
        conf.main = parsed["MAINNET"];
        conf.mainnet_addr = parsed["MAINNET_ADDR"];
        conf.testnet_addr = parsed["TESTNET_ADDR"];
        conf.announce_channel = parsed["DHT_ANNOUNCEMENT"];
        conf.block_channel = parsed["DHT_BLOCK"];
        conf.port = parsed["PORT"];
        conf.node_id = parsed["NODE_ID"];
        
    }catch(const exception& e){
        std::cerr<<"Error reading config file:: "<<e.what()<<std::endl;
        return -1;
    }
    std::shared_ptr<Logger> logger = std::make_shared<Logger>();
    std::shared_ptr<Identity> id = std::make_shared<Identity>(argv[2]);
    
    std::unique_ptr<Blockchain> blockchain = std::make_unique<Blockchain>(conf,id,logger);
    blockchain->AddKnownNodes("nodes.json");
    // auto b = new Blockchain(conf,logger);

    asciiPrint();
    while(true){
        const char* line_read = readline((conf.main?"[MAINNET]:>>":"[TESTNET]:>>"));
        if (line_read && *line_read)
            add_history(line_read);
        std::string line(line_read);
        if (!line.empty() && line[0] == '\0')
            break;

        if(line == "start"){
            logger->Debug("Starting blockchain");
            blockchain->Start();
        }
        if(line == "h" || line == "help"){
            printHelp();
            continue;
        }
        if(line == "status"){
            logger->Info((blockchain->IsRunning()?"Running.":"Inactive."));
            continue;
        }
        if(line=="routing"){
            logger->Info(blockchain->DHTRoutingTable());
            continue;
        }
        if(line=="nodes"){
            blockchain->DHTNodes();
            // logger->Info(nodes.toString());
            continue;
        }
        // if(line == "test1"){
        //     json j;
        //     j["userid"] = "1234";
        //     j["signed"] = "signed_auth_key";
        //     blockchain->dht_net_->Put(conf.internal_channel,0,j,[&logger](bool success){
        //         logger->Debug("Put operation ",(success?"Succcess":"Failure"));
        //     });

        // }
    }
    
}
void printHelp(){
    std::cout<<"h - print this message"<<std::endl;
    std::cout<<"start - start block chain"<<std::endl;
    // std::cout<<"h - print this message"<<std::endl;
}
void asciiPrint(){
    std::cout<<R"(  _______     _____ _____ _____   __  __    _    ____ _____ _____ ____  _   _  ___  ____  _____ 
 | ____\ \   / / _ \_   _| ____| |  \/  |  / \  / ___|_   _| ____|  _ \| \ | |/ _ \|  _ \| ____|
 |  _|  \ \ / / | | || | |  _|   | |\/| | / _ \ \___ \ | | |  _| | |_) |  \| | | | | | | |  _|  
 | |___  \ V /| |_| || | | |___  | |  | |/ ___ \ ___) || | | |___|  _ <| |\  | |_| | |_| | |___ 
 |_____|  \_/  \___/ |_| |_____| |_|  |_/_/   \_\____/ |_| |_____|_| \_\_| \_|\___/|____/|_____|
                                                                                               )"<<endl;
}
