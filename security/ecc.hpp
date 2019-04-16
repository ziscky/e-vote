#ifndef ECC_HPP
#define ECC_HPP

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



struct B64KeyPair{
    std::string public_key;
    std::string private_key;

    B64KeyPair(std::string pub,std::string priv):public_key(pub),private_key(priv){}
    friend std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp);

};

struct HexKeyPair{
    std::string public_key;
    std::string private_key;

    HexKeyPair(std::string pub,std::string priv):public_key(pub),private_key(priv){}
    friend std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp);
};

std::ostream& operator<<(std::ostream& stream,const B64KeyPair& kp){
    stream<<"Public Key: "<<kp.public_key<<std::endl;
    stream<<"Private Key: "<<kp.private_key<<std::endl;
    return stream;
}

std::ostream& operator<<(std::ostream& stream,const HexKeyPair& kp){
    stream<<"Public Key: "<<kp.public_key<<std::endl;
    stream<<"Private Key: "<<kp.private_key<<std::endl;
    return stream;
}


struct KeyPair{
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey private_key;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey public_key;

    KeyPair(CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey priv,CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey pub):private_key(priv),public_key(pub){}
};


template <typename T>
class KeyGen{
    public:
        KeyGen(bool deterministic):deterministic_(deterministic){};
        ~KeyGen(){};
        T GenerateKeys(std::string passwd);
        T GenerateKeys();
        KeyPair LoadKeys(const T&);
        bool TestDSKeys(const KeyPair&);

    private:
        const bool deterministic_;
        T GenerateDeterministicKeys(std::string);
        T GenerateRandomKeys();
        KeyPair ECCKeyGen(CryptoPP::RandomNumberGenerator&);
        CryptoPP::SecByteBlock DeriveKey(const std::string&,const std::string&);
        T EncodeKeyPair(const KeyPair&);
        std::string TestPRNG(CryptoPP::RandomNumberGenerator&);

};


template<typename T> T KeyGen<T>::GenerateKeys(std::string passwd){
    if(!this->deterministic_){
        //generate random key if not set to 
        std::cout<<"Defaulting to random key"<<std::endl;
        return this->GenerateRandomKeys();
    }
    return this->GenerateDeterministicKeys(passwd);   
}

template<typename T> T KeyGen<T>::GenerateKeys(){
    std::cout<<"Here"<<std::endl;
    if(this->deterministic_)
        throw new std::string("Call with passwd for deterministic generation");
    return this->GenerateRandomKeys();
}


template<typename T> T KeyGen<T>::GenerateRandomKeys(){
    CryptoPP::AutoSeededRandomPool prng;
    auto keypair = this->ECCKeyGen( prng);
    return this->EncodeKeyPair(keypair);
}    


template<typename T> T KeyGen<T>::GenerateDeterministicKeys(std::string passwd){ 
    auto seed = this->DeriveKey(passwd,"e-vote");

    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption prng;
    //
    //pointer to beginning of secbyte_block,size of the block, pinter to beginning of IV 
    prng.SetKeyWithIV(seed,32,seed+32,16);    
    
    //test PRNG determinism
    {
        std::string prev;
        for(int i=0;i<2;i++){
            CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption prng;
            prng.SetKeyWithIV(seed,32,seed+32,16);
            if(prev.length() == 0){
                prev = this->TestPRNG(prng);
                continue;
            }
            if (this->TestPRNG(prng) != prev){
                throw std::string("Invalid PRNG behaviour");
            }

        }

    }

    auto keypair = this->ECCKeyGen(prng);
    return this->EncodeKeyPair(keypair);
}    

//returns a constant length derived key from the password and salt using the scrypt algorithm.
template <typename T> CryptoPP::SecByteBlock KeyGen<T>::DeriveKey(const std::string& passwd,const std::string& salt){
    //Using scrypt for key derivation
    //32 bit key plus 16 bit Initialization vector.
    CryptoPP::SecByteBlock derived(32+16);
    CryptoPP::Scrypt scrypt;
    //dest,dest_size,pointer to first char of the password,size of the password,pointer to the first char of the salt,length of the salt,
    scrypt.DeriveKey(derived,derived.size(),(const CryptoPP::byte*)&passwd[0],passwd.size(),(const CryptoPP::byte*)&salt[0],salt.size(),1024,8,16);
    return derived;

}

//returns an Elliptic curve public/private keypair generated using the standard curve p=521 as defined by NIST
template<typename T> KeyPair KeyGen<T>::ECCKeyGen(CryptoPP::RandomNumberGenerator& prng){
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey private_key;
    
    private_key.Initialize(prng,CryptoPP::ASN1::secp521r1());
    private_key.ThrowIfInvalid(prng,3);

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    public_key.ThrowIfInvalid(prng,3);

    return KeyPair(private_key,public_key);
}


template<> KeyPair KeyGen<B64KeyPair>::LoadKeys(const B64KeyPair& encoded_keypair){
    std::string public_key( encoded_keypair.public_key);
    std::string private_key(encoded_keypair.private_key);
    CryptoPP::HexDecoder priv_decoder,pub_decoder1,pub_decoder2;
    priv_decoder.Put((CryptoPP::byte*)&private_key[0],private_key.size());
    priv_decoder.MessageEnd();


    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey PrivateKey;
    CryptoPP::Integer private_exponent;
    private_exponent.Decode(priv_decoder,priv_decoder.MaxRetrievable());
    PrivateKey.Initialize(CryptoPP::ASN1::secp521r1(),private_exponent);
    std::cout<<"Private key init"<<std::endl;


    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey PublicKey;
    CryptoPP::ECPPoint public_elem;
    std::cout<<public_key<<std::endl;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::StringSource source(public_key,true,new CryptoPP::Base64Decoder);
    PublicKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    PublicKey.GetGroupParameters().GetCurve().DecodePoint(public_elem,source,source.MaxRetrievable());
    PublicKey.SetPublicElement(public_elem);
    PublicKey.ThrowIfInvalid(prng,3);
    std::cout << "X: " << std::hex << public_elem.x << endl;
    std::cout << "Y: " << std::hex << public_elem.y << endl;
    std::cout<<"Public key init"<<std::endl;
    return KeyPair(PrivateKey,PublicKey);
}

template<> KeyPair KeyGen<HexKeyPair>::LoadKeys(const HexKeyPair& encoded_keypair){
    std::string public_key( encoded_keypair.public_key);
    std::string private_key(encoded_keypair.private_key);
    CryptoPP::HexDecoder priv_decoder,pub_decoder1,pub_decoder2;
    priv_decoder.Put((CryptoPP::byte*)&private_key[0],private_key.size());
    priv_decoder.MessageEnd();


    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey PrivateKey;
    CryptoPP::Integer private_exponent;
    private_exponent.Decode(priv_decoder,priv_decoder.MaxRetrievable());
    PrivateKey.Initialize(CryptoPP::ASN1::secp521r1(),private_exponent);
    std::cout<<"Private key init"<<std::endl;


    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey PublicKey;
    CryptoPP::ECPPoint public_elem;
    std::cout<<public_key<<std::endl;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::StringSource source(public_key,true,new CryptoPP::HexDecoder);
    PublicKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    PublicKey.GetGroupParameters().GetCurve().DecodePoint(public_elem,source,source.MaxRetrievable());
    PublicKey.SetPublicElement(public_elem);
    PublicKey.ThrowIfInvalid(prng,3);
    std::cout << "X: " << std::hex << public_elem.x << endl;
    std::cout << "Y: " << std::hex << public_elem.y << endl;
    std::cout<<"Public key init"<<std::endl;
    return KeyPair(PrivateKey,PublicKey);
}

template<> HexKeyPair KeyGen<HexKeyPair>::EncodeKeyPair(const KeyPair& keypair){
    const CryptoPP::Integer& private_exp =  keypair.private_key.GetPrivateExponent();
    const CryptoPP::ECPPoint& public_elem = keypair.public_key.GetPublicElement();

    std::string public_key_str;
    CryptoPP::SecByteBlock sec_byte(keypair.public_key.GetGroupParameters().GetCurve().EncodedPointSize(true));
    keypair.public_key.GetGroupParameters().GetCurve().EncodePoint(sec_byte,public_elem,true);
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(public_key_str));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::ArraySource src(sec_byte,sec_byte.size(),true,new CryptoPP::Redirector(cs));

    std::stringstream ss;
    ss<<std::hex<<private_exp;
    std::string private_key_str = ss.str();
    return HexKeyPair(public_key_str,private_key_str);
}

template<> B64KeyPair KeyGen<B64KeyPair>::EncodeKeyPair(const KeyPair& keypair){
    const CryptoPP::Integer& private_exp =  keypair.private_key.GetPrivateExponent();
    const CryptoPP::ECPPoint& public_elem = keypair.public_key.GetPublicElement();

    CryptoPP::SecByteBlock sec_byte(keypair.public_key.GetGroupParameters().GetCurve().EncodedPointSize(true));
    keypair.public_key.GetGroupParameters().GetCurve().EncodePoint(sec_byte,public_elem,true);

    std::string public_key_str;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(public_key_str));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::ArraySource src(sec_byte,sec_byte.size(),true,new CryptoPP::Redirector(cs));

    std::stringstream ss;
    ss<<std::hex<<private_exp;
    std::string private_key_str = ss.str();
    return B64KeyPair(public_key_str,private_key_str);
}

template<typename T> bool KeyGen<T>::TestDSKeys(const KeyPair& keypair){
    CryptoPP::AutoSeededRandomPool prng;
    //Test message signing and verification
    std::string plain("plaintext");
    std::string sign;

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(keypair.private_key);
    CryptoPP::StringSource s(plain,true,new CryptoPP::SignerFilter(prng,signer,new CryptoPP::StringSink(sign)));
    std::cout<<sign<<std::endl;

    bool res;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier ver(keypair.public_key);
    CryptoPP::StringSource ss(sign+plain+"x",true,new CryptoPP::SignatureVerificationFilter(ver,new CryptoPP::ArraySink((CryptoPP::byte*)&res,sizeof(res))));
    return res;

}

template<typename T> std::string KeyGen<T>::TestPRNG(CryptoPP::RandomNumberGenerator& rng){
    
    CryptoPP::SecByteBlock block(16);
    rng.GenerateBlock(block,block.size());    
    std::string s;
    CryptoPP::HexEncoder hex(new CryptoPP::StringSink(s));
    hex.Put(block, block.size());
    hex.MessageEnd();
    return s;
}
#endif