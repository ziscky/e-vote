#ifndef IDENTITY_HPP
#define IDENTITY_HPP

#include <iostream>
#include <fstream>
#include "ecc.hpp"
#include "utils/json.hpp"
#include "utils/utils.hpp"
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/channels.h>   


class Identity{
    public:
        Identity(std::string public_key,std::string private_key,std::string e_public_key,std::string e_private_key);
        Identity(std::string path);
        // ~Identity();
        std::string SignData(std::string);
        std::string EncryptData(std::string);
        std::string DecryptData(std::string);
        bool VerifyData(std::string,std::string);

    private:
        std::unique_ptr<HexKeyPair> encoded_keypair_;
        std::unique_ptr<KeyGen<HexKeyPair>> keygen_;
        std::unique_ptr<KeyPair> keypair_;
};


Identity::Identity(std::string public_key,std::string private_key,std::string e_public_key,std::string e_private_key){
    encoded_keypair_ = std::make_unique<HexKeyPair>(public_key,private_key,e_public_key,e_private_key);
    keygen_ = std::make_unique<KeyGen<HexKeyPair>>(false);

    keypair_ = std::make_unique<KeyPair>(keygen_->LoadKeys(*(encoded_keypair_.get())));

    // std::cout<<keypair_->public_key.GetPublicElement()<<std::endl;
}

Identity::Identity(std::string path){
    std::ifstream conf_file(path);
    nlohmann::json parsed;
    conf_file >> parsed;
    Identity(parsed["dsa_pub"],parsed["dsa_priv"],parsed["ecies_pub"],parsed["ecies_priv"]);
}

std::string Identity::SignData(std::string data){
    std::string signature,signature_encoded;

    CryptoPP::AutoSeededRandomPool prng;

    //create signer from private key
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(this->keypair_->private_key);
    
    //use cryptopp filter to parse data and sign to signature string.
    CryptoPP::StringSource source_(data,true,new CryptoPP::SignerFilter(prng,signer,new CryptoPP::StringSink(signature)));
    
    //create hex encoder
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(signature_encoded));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::StringSource src(signature,true,new CryptoPP::Redirector(cs));
    return signature_encoded;
}

bool Identity::VerifyData(std::string data,std::string signature_encoded){
    bool res = false;
    std::string signature;

    CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(signature));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(decoder);

    CryptoPP::StringSource source_(signature_encoded,true,new CryptoPP::Redirector(cs));
    

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(this->keypair_->public_key);
    CryptoPP::StringSource ss(signature+data,true,new CryptoPP::SignatureVerificationFilter(verifier,new CryptoPP::ArraySink((CryptoPP::byte*)&res,sizeof(res))));

    return res;
}

std::string Identity::EncryptData(std::string plain){
    CryptoPP::AutoSeededRandomPool prng;
    std::string cipher;
    CryptoPP::StringSource src(plain,true,new CryptoPP::PK_EncryptorFilter(prng,this->keypair_->e_public_key,new CryptoPP::StringSink(cipher)));
    return cipher;

}

std::string Identity::DecryptData(std::string cipher){
    CryptoPP::AutoSeededRandomPool prng;
    std::string plain;
    CryptoPP::StringSource src(cipher,true,new CryptoPP::PK_DecryptorFilter(prng,this->keypair_->e_private_key,new CryptoPP::StringSink(plain)));
    return plain;

}


#endif