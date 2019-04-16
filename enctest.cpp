#include "security/ecc.hpp"

#include <iostream>
#include <string>



int main(){
    KeyGen<B64KeyPair> keygen(true);
    while(true){
        std::cout<<"enter key: ";
        char key[100];
        std::cin>>key;
        
        // keygen.test();
        std::string kstr(key);
        std::cout<<std::endl<<"Setting key: "<<kstr<<std::endl;
        auto keys = keygen.GenerateKeys(kstr);
        std::cout<<keys;
        auto initKeys = keygen.LoadKeys(keys);
        auto v = keygen.TestDSKeys(initKeys);
        if(v){
            std::cout<<"Keys are valid"<<std::endl;
        }
    }
}

