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
#include <cryptopp/dsa.h>        
#include <cryptopp/integer.h>    
#include <cryptopp/hex.h>     
#include <cryptopp/base64.h>
#include <cryptopp/asn.h>  
#include <cryptopp/oids.h>
#include <cryptopp/channels.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/hkdf.h>
#include "ecc.hpp"
#include "utils/json.hpp"
#include "utils/utils.hpp"


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
    //----------------------------ECDSA--------------------------------------------//
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey private_key;
    
    private_key.Initialize(prng,CryptoPP::ASN1::secp521r1());
    private_key.ThrowIfInvalid(prng,3);

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    public_key.ThrowIfInvalid(prng,3);

    //-----------------------------ECIES---------------------------------------------//
    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor e_private_key(prng,CryptoPP::ASN1::secp521r1());
    e_private_key.GetPrivateKey().ThrowIfInvalid(prng,3);


    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e_public_key(e_private_key);
    e_public_key.GetPublicKey().ThrowIfInvalid(prng,3);

    return KeyPair(private_key,public_key,e_public_key,e_private_key);
}


template<> KeyPair KeyGen<B64KeyPair>::LoadKeys(const B64KeyPair& encoded_keypair){
    CryptoPP::AutoSeededRandomPool prng;

    //-----------------------------ECDSA-----------------------------------------//
    std::string public_key( encoded_keypair.public_key);
    std::string private_key(encoded_keypair.private_key);

    //private key
    CryptoPP::Base64Decoder priv_decoder,pub_decoder;
    //initialize decoder
    priv_decoder.Put((CryptoPP::byte*)&private_key[0],private_key.size());
    priv_decoder.MessageEnd();

    //decode private exponent
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey PrivateKey;

    CryptoPP::Integer private_exponent;
    private_exponent.Decode(priv_decoder,priv_decoder.MaxRetrievable());
    PrivateKey.Initialize(CryptoPP::ASN1::secp521r1(),private_exponent);
    std::cout<<"Private key init"<<std::endl;

    //public key
    CryptoPP::StringSource source(public_key,true,new CryptoPP::Base64Decoder);
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey PublicKey;
    CryptoPP::ECPPoint public_elem;
    
    //decode and initialize public element from decoded string
    PublicKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    PublicKey.GetGroupParameters().GetCurve().DecodePoint(public_elem,source,source.MaxRetrievable());
    PublicKey.SetPublicElement(public_elem);
    PublicKey.ThrowIfInvalid(prng,3);
    


    //-----------------------------ECIES-----------------------------------------//
    std::string e_public_key( encoded_keypair.e_public_key);
    std::string e_private_key(encoded_keypair.e_private_key);

    //private key
    CryptoPP::Base64Decoder e_priv_decoder;
    //load the encoded key into the b64 decoder
    e_priv_decoder.Put((CryptoPP::byte*)&e_private_key[0],e_private_key.size());
    e_priv_decoder.MessageEnd();

    //decode the private exponent from the string
    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor E_PrivateKey;
    CryptoPP::Integer e_private_exponent;
    e_private_exponent.Decode(e_priv_decoder,e_priv_decoder.MaxRetrievable());
    //initialize a p=521 curve withe the decoded private exponent
    E_PrivateKey.AccessKey().Initialize(CryptoPP::ASN1::secp521r1(),e_private_exponent);


    //public key
    CryptoPP::StringSource e_source(e_public_key,true,new CryptoPP::Base64Decoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor E_PublicKey;
    CryptoPP::ECPPoint e_public_elem;

    //decode the public element from the string 
    E_PublicKey.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    E_PublicKey.GetKey().GetGroupParameters().GetCurve().DecodePoint(e_public_elem,e_source,e_source.MaxRetrievable());
    //initialize the public key using the decoded public element
    E_PublicKey.AccessKey().SetPublicElement(e_public_elem);
    E_PublicKey.AccessKey().ThrowIfInvalid(prng,3);
    

    return KeyPair(PrivateKey,PublicKey,E_PrivateKey,E_PublicKey);
}

template<> KeyPair KeyGen<HexKeyPair>::LoadKeys(const HexKeyPair& encoded_keypair){
    CryptoPP::AutoSeededRandomPool prng;

    //-----------------------------ECDSA-----------------------------------------//
    std::string public_key( encoded_keypair.public_key);
    std::string private_key(encoded_keypair.private_key);

    //private key
    CryptoPP::HexDecoder priv_decoder,pub_decoder;
    //load private key into decoder
    priv_decoder.Put((CryptoPP::byte*)&private_key[0],private_key.size());
    priv_decoder.MessageEnd();
    
    //decode the private exponent from the decoded hex
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PrivateKey PrivateKey;
    CryptoPP::Integer private_exponent;
    private_exponent.Decode(priv_decoder,priv_decoder.MaxRetrievable());
    PrivateKey.Initialize(CryptoPP::ASN1::secp521r1(),private_exponent);
    

    //public key
    CryptoPP::StringSource source(public_key,true,new CryptoPP::HexDecoder);
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::PublicKey PublicKey;
    CryptoPP::ECPPoint public_elem;
    
    
    PublicKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    PublicKey.GetGroupParameters().GetCurve().DecodePoint(public_elem,source,source.MaxRetrievable());
    PublicKey.SetPublicElement(public_elem);
    PublicKey.ThrowIfInvalid(prng,3);
    


    //-----------------------------ECIES-----------------------------------------//
    std::string e_public_key( encoded_keypair.e_public_key);
    std::string e_private_key(encoded_keypair.e_private_key);

    //private key
    CryptoPP::HexDecoder e_priv_decoder;
    e_priv_decoder.Put((CryptoPP::byte*)&e_private_key[0],e_private_key.size());
    e_priv_decoder.MessageEnd();
    
    //decode private exponent from the desired key
    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor E_PrivateKey;
    CryptoPP::Integer e_private_exponent;
    e_private_exponent.Decode(e_priv_decoder,e_priv_decoder.MaxRetrievable());
    E_PrivateKey.AccessKey().Initialize(CryptoPP::ASN1::secp521r1(),e_private_exponent);

    //public key
    CryptoPP::StringSource e_source(e_public_key,true,new CryptoPP::HexDecoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor E_PublicKey;
    CryptoPP::ECPPoint e_public_elem;
    
    //decode the public key from the public element
    E_PublicKey.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());
    E_PublicKey.GetKey().GetGroupParameters().GetCurve().DecodePoint(e_public_elem,e_source,e_source.MaxRetrievable());
    E_PublicKey.AccessKey().SetPublicElement(e_public_elem);
    E_PublicKey.AccessKey().ThrowIfInvalid(prng,3);
    

    return KeyPair(PrivateKey,PublicKey,E_PublicKey,E_PrivateKey);
}

template<> HexKeyPair KeyGen<HexKeyPair>::EncodeKeyPair(const KeyPair& keypair){

     //ECDSA keypair strings in hex format
    std::string public_key_str;
    std::string private_key_str;

    //EIES keypair strings in hex format
    std::string e_public_key_str;
    std::string e_private_key_str;


    //create hex encoder to store result in public_key_str
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(public_key_str));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::HexEncoder priv_encoder(new CryptoPP::StringSink(private_key_str));
    CryptoPP::ChannelSwitch priv_cs;
    priv_cs.AddDefaultRoute(priv_encoder);

    CryptoPP::HexEncoder ecies_pub_encoder(new CryptoPP::StringSink(e_public_key_str));
    CryptoPP::ChannelSwitch ecies_pub_cs;
    ecies_pub_cs.AddDefaultRoute(ecies_pub_encoder);

    CryptoPP::HexEncoder ecies_priv_encoder(new CryptoPP::StringSink(e_private_key_str));
    CryptoPP::ChannelSwitch ecies_priv_cs;
    ecies_priv_cs.AddDefaultRoute(ecies_priv_encoder);
    

    //--------------------------------ECDSA---------------------------------------------------------//
    //retrieve private exponent
    const CryptoPP::Integer& private_exp =  keypair.private_key.GetPrivateExponent();
    //retrieve public element
    const CryptoPP::ECPPoint& public_elem = keypair.public_key.GetPublicElement();
    //create a byte of the size = min. public key size(i.e compressed)
    CryptoPP::SecByteBlock sec_byte(keypair.public_key.GetGroupParameters().GetCurve().EncodedPointSize(true));
    //encode the public element in compressed format to sec_byte
    keypair.public_key.GetGroupParameters().GetCurve().EncodePoint(sec_byte,public_elem,true);
    CryptoPP::ArraySource src(sec_byte,sec_byte.size(),true,new CryptoPP::Redirector(cs));

    //
    CryptoPP::SecByteBlock sec_priv(private_exp.MinEncodedSize());
    private_exp.Encode(sec_priv,sec_priv.size());
    CryptoPP::ArraySource src_priv(sec_priv,sec_priv.size(),true,new CryptoPP::Redirector(priv_encoder));
    

    //--------------------------------ECIES---------------------------------------------------------//
    //retrieve the private exponent
    const CryptoPP::Integer& e_private_exp =  keypair.e_private_key.GetKey().GetPrivateExponent();
    //create a byte of size = min. private exponent size
    CryptoPP::SecByteBlock sec(e_private_exp.MinEncodedSize());
    //encode the private exponent into the sec_byte
    e_private_exp.Encode(sec,sec.size());
    CryptoPP::ArraySource src1(sec,sec.size(),true,new CryptoPP::Redirector(ecies_priv_cs));

    //retrieve the base public element form the pub key.
    const CryptoPP::ECPPoint& e_public_elem = keypair.e_public_key.GetKey().GetGroupParameters().ExponentiateBase(e_private_exp);
    //create sec_byte of min. possible public key size
    CryptoPP::SecByteBlock sec_pub(keypair.e_public_key.GetKey().GetGroupParameters().GetCurve().EncodedPointSize(true));
    //encode the compressed public key
    keypair.e_public_key.GetKey().GetGroupParameters().GetCurve().EncodePoint(sec_pub,e_public_elem,true);
    CryptoPP::ArraySource(sec_pub,sec_pub.size(),true,new CryptoPP::Redirector(ecies_pub_cs));

    

    return HexKeyPair(public_key_str,private_key_str,e_public_key_str,e_private_key_str);
}

template<> B64KeyPair KeyGen<B64KeyPair>::EncodeKeyPair(const KeyPair& keypair){
    //ECDSA keypair strings in hex format
    std::string public_key_str;
    std::string private_key_str;

    //EIES keypair strings in hex format
    std::string e_public_key_str;
    std::string e_private_key_str;


    //create hex encoder to store result in public_key_str
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(public_key_str));
    CryptoPP::ChannelSwitch cs;
    cs.AddDefaultRoute(encoder);

    CryptoPP::Base64Encoder priv_encoder(new CryptoPP::StringSink(private_key_str));
    CryptoPP::ChannelSwitch priv_cs;
    priv_cs.AddDefaultRoute(priv_encoder);

    CryptoPP::Base64Encoder ecies_pub_encoder(new CryptoPP::StringSink(e_public_key_str));
    CryptoPP::ChannelSwitch ecies_pub_cs;
    ecies_pub_cs.AddDefaultRoute(ecies_pub_encoder);

    CryptoPP::Base64Encoder ecies_priv_encoder(new CryptoPP::StringSink(e_private_key_str));
    CryptoPP::ChannelSwitch ecies_priv_cs;
    ecies_priv_cs.AddDefaultRoute(ecies_priv_encoder);
    

    //--------------------------------ECDSA---------------------------------------------------------//
    //retrieve private exponent
    const CryptoPP::Integer& private_exp =  keypair.private_key.GetPrivateExponent();
    //retrieve public element
    const CryptoPP::ECPPoint& public_elem = keypair.public_key.GetPublicElement();
    //create a byte of the size = min. public key size(i.e compressed)
    CryptoPP::SecByteBlock sec_byte(keypair.public_key.GetGroupParameters().GetCurve().EncodedPointSize(true));
    //encode the public element in compressed format to sec_byte
    keypair.public_key.GetGroupParameters().GetCurve().EncodePoint(sec_byte,public_elem,true);
    CryptoPP::ArraySource src(sec_byte,sec_byte.size(),true,new CryptoPP::Redirector(cs));

    //
    CryptoPP::SecByteBlock sec_priv(private_exp.MinEncodedSize());
    private_exp.Encode(sec_priv,sec_priv.size());
    CryptoPP::ArraySource src_priv(sec_priv,sec_priv.size(),true,new CryptoPP::Redirector(priv_encoder));
    // std::stringstream ss;
    // ss<<std::hex<<sec_priv;
    // private_key_str = ss.str();
    

    //--------------------------------ECIES---------------------------------------------------------//
    //retrieve the private exponent
    const CryptoPP::Integer& e_private_exp =  keypair.e_private_key.GetKey().GetPrivateExponent();
    //create a byte of size = min. private exponent size
    CryptoPP::SecByteBlock sec(e_private_exp.MinEncodedSize());
    //encode the private exponent into the sec_byte
    e_private_exp.Encode(sec,sec.size());
    CryptoPP::ArraySource src1(sec,sec.size(),true,new CryptoPP::Redirector(ecies_priv_cs));

    //retrieve the base public element form the pub key.
    const CryptoPP::ECPPoint& e_public_elem = keypair.e_public_key.GetKey().GetGroupParameters().ExponentiateBase(e_private_exp);
    //create sec_byte of min. possible public key size
    CryptoPP::SecByteBlock sec_pub(keypair.e_public_key.GetKey().GetGroupParameters().GetCurve().EncodedPointSize(true));
    //encode the compressed public key
    keypair.e_public_key.GetKey().GetGroupParameters().GetCurve().EncodePoint(sec_pub,e_public_elem,true);
    CryptoPP::ArraySource(sec_pub,sec_pub.size(),true,new CryptoPP::Redirector(ecies_pub_cs));



    return B64KeyPair(public_key_str,private_key_str,e_public_key_str,e_private_key_str);
}

template<typename T> bool KeyGen<T>::TestDSKeys(const KeyPair& keypair){
    CryptoPP::AutoSeededRandomPool prng;
    //Test message signing and verification
    std::string plain("plaintext");
    std::string sign;

    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Signer signer(keypair.private_key);
    CryptoPP::StringSource s(plain,true,new CryptoPP::SignerFilter(prng,signer,new CryptoPP::StringSink(sign)));
    // std::cout<<sign<<std::endl;

    bool res = false;
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA256>::Verifier ver(keypair.public_key);
    CryptoPP::StringSource ss(sign+plain,true,new CryptoPP::SignatureVerificationFilter(ver,new CryptoPP::ArraySink((CryptoPP::byte*)&res,sizeof(res))));
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

template class KeyGen<HexKeyPair>;
template class KeyGen<B64KeyPair>;