
#include <iostream>
#include <fstream>
#include "identity.hpp"
#include "utils/json.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>      
#include <cryptopp/modes.h>
#include <cryptopp/eccrypto.h>   
#include <cryptopp/ecp.h>
#include <cryptopp/dsa.h>        
#include <cryptopp/integer.h>    
#include <cryptopp/hex.h>     
#include <cryptopp/base64.h>
#include <cryptopp/asn.h>  
#include <cryptopp/oids.h>
#include <cryptopp/channels.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>

Identity::Identity(std::string public_key,std::string private_key,std::string e_public_key,std::string e_private_key){
    encoded_keypair_ = std::make_unique<HexKeyPair>(public_key,private_key,e_public_key,e_private_key);
    keygen_ = std::make_unique<KeyGen<HexKeyPair>>(false);

    keypair_ = std::make_unique<KeyPair>(keygen_->LoadKeys(*(encoded_keypair_.get())));

}

Identity::Identity(const std::string& path){
    std::ifstream conf_file(path);
    nlohmann::json parsed;
    conf_file >> parsed;
    
    encoded_keypair_ = std::make_unique<HexKeyPair>(parsed["dsa_pub"],parsed["dsa_priv"],parsed["ecies_pub"],parsed["ecies_priv"]);
    keygen_ = std::make_unique<KeyGen<HexKeyPair>>(false);

    keypair_ = std::make_unique<KeyPair>(keygen_->LoadKeys(*(encoded_keypair_.get())));
}

std::string Identity::IESPublicKey(){
    return this->encoded_keypair_->e_public_key;
}

std::string Identity::DSAPublicKey(){
    return this->encoded_keypair_->public_key;
}


std::string Identity::SignData(const std::string& data){
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

bool Identity::VerifyData(const std::string& data,const std::string& signature_encoded){
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

bool Identity::VerifyData(const std::string& public_key,const std::string& data,const std::string& signature_encoded){
    bool res = false;
    std::string signature;

    CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(signature));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(decoder);
 
    CryptoPP::StringSource source_(signature_encoded,true,new CryptoPP::Redirector(cs));
 
    CryptoPP::AutoSeededRandomPool prng;
    //public key
    CryptoPP::StringSource e_source(public_key,true,new CryptoPP::HexDecoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor E_PublicKey;
    CryptoPP::ECPPoint e_public_elem;
    
    //decode the public key from the public element
    E_PublicKey.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    E_PublicKey.GetKey().GetGroupParameters().GetCurve().DecodePoint(e_public_elem,e_source,e_source.MaxRetrievable());
    E_PublicKey.AccessKey().SetPublicElement(e_public_elem);
    E_PublicKey.AccessKey().ThrowIfInvalid(prng,3);
 
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier verifier(E_PublicKey);
    CryptoPP::StringSource ss(signature+data,true,new CryptoPP::SignatureVerificationFilter(verifier,new CryptoPP::ArraySink((CryptoPP::byte*)&res,sizeof(res))));
 
    return res;
}

std::string Identity::EncryptData(const std::string& plain){
    CryptoPP::AutoSeededRandomPool prng;
    std::string cipher,cipher_encoded;
    CryptoPP::StringSource src(plain,true,new CryptoPP::PK_EncryptorFilter(prng,this->keypair_->e_public_key,new CryptoPP::StringSink(cipher)));
    
    //create hex encoder
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(cipher_encoded));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::StringSource src1(cipher,true,new CryptoPP::Redirector(cs));

    return cipher_encoded;

}

std::string Identity::DecryptData(const std::string& cipher_encoded){
    std::string cipher;
    CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(cipher));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(decoder);

    CryptoPP::StringSource source_(cipher_encoded,true,new CryptoPP::Redirector(cs));
    

    CryptoPP::AutoSeededRandomPool prng;
    std::string plain;
    CryptoPP::StringSource src(cipher,true,new CryptoPP::PK_DecryptorFilter(prng,this->keypair_->e_private_key,new CryptoPP::StringSink(plain)));
    return plain;

}

std::string Identity::EncryptData(const std::string& public_key,const std::string& plain){
    CryptoPP::AutoSeededRandomPool prng;
    //public key
    CryptoPP::StringSource e_source(public_key,true,new CryptoPP::HexDecoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor E_PublicKey;
    CryptoPP::ECPPoint e_public_elem;
    
    //decode the public key from the public element
    E_PublicKey.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    E_PublicKey.GetKey().GetGroupParameters().GetCurve().DecodePoint(e_public_elem,e_source,e_source.MaxRetrievable());
    E_PublicKey.AccessKey().SetPublicElement(e_public_elem);
    E_PublicKey.AccessKey().ThrowIfInvalid(prng,3);

    std::string cipher,cipher_encoded;
    CryptoPP::StringSource src(plain,true,new CryptoPP::PK_EncryptorFilter(prng,E_PublicKey,new CryptoPP::StringSink(cipher)));

     //create hex encoder
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(cipher_encoded));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::StringSource src1(cipher,true,new CryptoPP::Redirector(cs));
    return cipher_encoded;
    
}

std::string Identity::ComputeHash(const std::string& data){
    CryptoPP::SHA256 hash_func;
    std::string hash;
    CryptoPP::StringSource src(data,true,new CryptoPP::HashFilter(hash_func,new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
    return hash;
}
