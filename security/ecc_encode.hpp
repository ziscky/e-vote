#ifndef ECC_ENCODE_HPP
#define ECC_ENCODE_HPP

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <type_traits>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>      
#include <cryptopp/modes.h>
#include <cryptopp/eccrypto.h>   
#include <cryptopp/ecp.h>        
#include <cryptopp/integer.h>    
#include <cryptopp/hex.h>     
#include <cryptopp/base64.h>
#include <cryptopp/asn.h>  
#include <cryptopp/oids.h>
#include <cryptopp/channels.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/hkdf.h>
#include "utils/json.hpp"
#include "utils/utils.hpp"


struct KeyPair{
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey private_key;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey public_key;

    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor e_private_key;
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e_public_key;
    

    KeyPair(CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey priv,CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey pub,CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e_pub,CryptoPP::ECIES<CryptoPP::ECP>::Decryptor e_priv)
        :private_key(priv),public_key(pub),e_private_key(e_priv),e_public_key(e_pub){}
};


struct B64KeyPair{
    std::string public_key;
    std::string private_key;

    std::string e_public_key;
    std::string e_private_key;

    B64KeyPair(std::string pub,std::string priv,std::string e_pub,std::string e_priv):
        public_key(pub),private_key(priv),e_private_key(e_priv),e_public_key(e_pub){}
    friend std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp);

};

struct HexKeyPair{
    std::string public_key;
    std::string private_key;

    std::string e_public_key;
    std::string e_private_key;

    HexKeyPair(std::string pub,std::string priv,std::string e_pub,std::string e_priv):
        public_key(pub),private_key(priv),e_private_key(e_priv),e_public_key(e_pub){}
    friend std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp);
};

std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp){
    stream<<"DSA Public Key: "<<kp.public_key<<std::endl;
    stream<<"DSA Private Key: "<<kp.private_key<<std::endl;
    stream<<"ECIES Public Key: "<<kp.e_public_key<<std::endl;
    stream<<"ECIES Private Key: "<<kp.e_private_key<<std::endl;
    return stream;
}

std::ostream& operator<<(std::ostream& stream,const HexKeyPair& kp){
    stream<<"DSA Public Key: "<<kp.public_key<<std::endl;
    stream<<"DSA Private Key: "<<kp.private_key<<std::endl;
    stream<<"ECIES Public Key: "<<kp.e_public_key<<std::endl;
    stream<<"ECIES Private Key: "<<kp.e_private_key<<std::endl;
    return stream;
}


#endif