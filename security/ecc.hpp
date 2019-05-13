#ifndef ECC_HPP
#define ECC_HPP

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <type_traits>
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
    friend std::ostream& operator<<(std::ostream& stream,const HexKeyPair& kp);
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


#endif