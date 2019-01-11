#include <iostream>
#include <opendht.h>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <condition_variable>


class Node{
    public:
        std::string mId;
        dht::DhtRunner node;
        std::shared_ptr<std::condition_variable> cond;
        int port;
        bool r;
        
        std::mutex mmut;

        Node(std::string mid,int port,std::shared_ptr<std::condition_variable> c):mId(mid),port(port),r(false),cond(c){

        };
        ~Node(){};
        void sig(){
            // while(true){
                std::cout<<"Listening for keys"<<std::endl;
                // node.get()
                auto token = node.listen("key1",
                    [this](const std::vector<std::shared_ptr<dht::Value>>& values) {
                        for (const auto& v : values)
                            std::cout << "Found value: " << *v << std::endl;
                            r = true;
                            cond.get()->notify_all();
                        return false; // keep listening
                    }
                );
                // token.get();
                
            // }
        };
        bool isRun(){
            return r;
        }
        void start(){
            std::cout<<"[*] Listening for connections"<<std::endl;
            node.run(port,dht::crypto::generateIdentity(mId),true);
            node.bootstrap("127.0.0.1","41109");
            auto addrs = node.getPublicAddressStr();
            for (const auto& addr : addrs)
                std::cout << addr << std::endl;
            
            this->sig();
            std::unique_lock<std::mutex> mlock(mmut);
            // cond.wait(mlock,std::bind(&Node::isRun,this));
            // while(true){
            //     std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            //     std::cout<<"[*] Updating node"<<std::endl;
            //     node.loop();
                
            // }
            // std::cout<<"[*] Stopping"<<std::endl;
        };



};


int main(){

    std::condition_variable *cond = new std::condition_variable;
    std::shared_ptr<std::condition_variable> cptr(cond);
    std::mutex mtx;
    std::unique_lock<std::mutex> lck(mtx);


    Node node("node1",4222,cptr);
    node.start();
    

    cptr.get()->wait(lck,std::bind(&Node::isRun,&node));
    // dht::DhtRunner node;

    // node.run(4333,dht::crypto::generateIdentity("node1"),true);

    // std::vector<uint8_t> data(1,10);
    // for(auto i: data){
    //     std::cout<<"Put:"<<data[i]<<std::endl;
    // }  
    
    // node.put("req",data);

  

    // node.get("resp",[](const std::vector<std::shared_ptr<dht::Value>>& values){
    //     for(const auto& v : values){
    //         std::cout<<"Conn From:"<<v<<std::endl;
    //     return true;
    //     }
    // });
    // node.join();
}