#include <iostream>
#include <fstream>
#include <string>
#include <opendht.h>

#include <chrono>
#include <readline/readline.h>
#include <readline/history.h>
#include "blockchain/blockchain.hpp"
#include "blockchain/litechain.h"

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

            c["MAINNET"] = false;
            c["MAINNET_ADDR"] = "";
            c["MAINNET_PORT"] = "";
            c["TESTNET_ADDR"] = "";
            c["TESTNET_PORT"] = "";
            c["PORT"] = "";
            c["NODE_ID"] = "";
            std::ofstream out("conf.json");
            out<<std::setw(4)<<c;
            out.close();
            return 0;
        }
        if(argc<4){
            std::cerr<<"./binary {conf} {identity} {nodes}"<<std::endl;
            return -1;
        }
        std::ifstream conf_file(argv[1]);
        json parsed;
        conf_file >> parsed;

        conf.node_id = parsed["NODE_ID"];
        conf.main = parsed["MAINNET"];
        conf.mainnet_addr = parsed["MAINNET_ADDR"];
        conf.testnet_addr = parsed["TESTNET_ADDR"];
        conf.port = parsed["PORT"];
        conf.testnet_port = parsed["TESTNET_PORT"];
        conf.mainnet_port = parsed["MAINNET_PORT"];

        
    }catch(const exception& e){
        std::cerr<<"Error reading config file:: "<<e.what()<<std::endl;
        return -1;
    }
    std::shared_ptr<Logger> logger = std::make_shared<Logger>();
    std::shared_ptr<Identity> id = std::make_shared<Identity>(argv[2]);
    
    std::unique_ptr<Blockchain> blockchain = std::make_unique<Blockchain>(conf,id,logger);
    blockchain->AddKnownNodes(argv[3]);
    // auto b = new Blockchain(conf,logger);

    std::unique_ptr<Litechain> lite = std::make_unique<Litechain>(argv[1],argv[2]);
    lite->AddKnownNodes(argv[3]);

    asciiPrint();
    while(true){
        const char* line_read = readline((conf.main?"[MAINNET]:>>":"[TESTNET]:>>"));
        if (line_read && *line_read)
            add_history(line_read);
        if(line_read == NULL){
            break;
        }
        std::string line(line_read);
        if (!line.empty() && line[0] == '\0')
            break;

        if(line == "start"){
            logger->Debug("Starting blockchain");
            blockchain->Start();
        }
        if(line == "startlite"){
            logger->Debug("Starting Litechain");
            lite->Start();
        }
        if(line == "init"){
            nlohmann::json obj;
            std::ifstream conf_file("/home/emok/PycharmProjects/electionbackends/pubkey");

            conf_file >> obj;

            obj["timestamp"] = 124453622;
            lite->InitChain(obj.dump());
        }
        if(line == "litetx"){
            nlohmann::json obj;
            obj["tx"] = "data...";
            obj["timestamp"] = 122314241;
            lite->BroadcastTX(obj.dump());
        }
        if(line == "getbx"){
            std::cout<<lite->GetBlock(0,"PARENT")<<std::endl;
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
        if(line == "tx"){
            blockchain->BroadcastTransaction();
            continue;
        }
        if(line == "debug"){
            blockchain->PrintNodes();
            continue;
        }
        if(line == "viewtx"){
            blockchain->PrintTX();
            continue;
        }
        if(line == "viewbx"){
            blockchain->PrintBlocks();
            continue;
        }
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
