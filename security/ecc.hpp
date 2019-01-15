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
        void test(){std::cout<<"TEST";};

    private:
        const bool deterministic_;
        T GenerateDeterministicKeys(std::string);
        T GenerateRandomKeys();
        KeyPair ECCKeyGen(CryptoPP::RandomNumberGenerator&);
        void DeriveKey(CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption&,const std::string&,const std::string&);
        T EncodeKeyPair(const KeyPair&);

};


template<typename T> T KeyGen<T>::GenerateKeys(std::string passwd){
    if(!this->deterministic_)
        //generate random key if not set to determinism
        return this->GenerateRandomKeys();
    return this->GenerateDeterministicKeys(passwd);   
}

template<class T> 
T KeyGen<T>::GenerateKeys(){
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
    // CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;;
    this->DeriveKey(prng,passwd,"e-vote");
    auto keypair = this->ECCKeyGen(prng);
    return this->EncodeKeyPair(keypair);
    
}    

template <typename T> void KeyGen<T>::DeriveKey(CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption& prng,const std::string& passwd,const std::string& salt){
    //Using scrypt for key derivation
    CryptoPP::SecByteBlock derived(32+16);
    CryptoPP::Scrypt scrypt;
    scrypt.DeriveKey(derived,32,(const CryptoPP::byte*)&passwd[0],passwd.size(),(const CryptoPP::byte*)&salt[0],salt.size(),1024,8,16);
    prng.SetKeyWithIV(derived,32,derived+32,16);

}

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

void TestDSKeys(const B64KeyPair& keypair){
    std::string public_key(keypair.public_key);
    std::string private_key(keypair.private_key);
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

    //Test message signing and verification
    std::string plain("plaintext");
    std::string sign;

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(PrivateKey);
    CryptoPP::StringSource s(plain,true,new CryptoPP::SignerFilter(prng,signer,new CryptoPP::StringSink(sign)));
    std::cout<<sign<<std::endl;

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier ver(PublicKey);
    bool res;
    CryptoPP::StringSource ss(sign+plain+"x",true,new CryptoPP::SignatureVerificationFilter(ver,new CryptoPP::ArraySink((CryptoPP::byte*)&res,sizeof(res))));
    std::cout<<res<<std::endl;


}

#endif