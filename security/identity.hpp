#ifndef IDENTITY_HPP
#define IDENTITY_HPP

#include "ecc.hpp"

class Identity{
    public:
        Identity(std::string public_key,std::string private_key,std::string e_public_key,std::string e_private_key);
        explicit Identity(const std::string& path);
        // ~Identity();
        std::string SignData(const std::string&);
        std::string EncryptData(const std::string&);
        std::string DecryptData(const std::string&);
        bool VerifyData(const std::string&,const std::string&);

        std::string EncryptData(const std::string& public_key,const std::string& plain);
        bool VerifyData(const std::string& public_key,const std::string& data,const std::string& signature);
        std::string IESPublicKey();
        std::string DSAPublicKey();
        std::string ComputeHash(const std::string&);

    private:
        std::unique_ptr<HexKeyPair> encoded_keypair_;
        std::unique_ptr<KeyGen<HexKeyPair>> keygen_;
        std::unique_ptr<KeyPair> keypair_;
};



#endif