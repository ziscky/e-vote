#include "merkle.hpp"
#include <iostream>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

MerkleNode::MerkleNode(std::string val){
    this->value_ = val;
    this->hash_ = this->ComputeHash();
    this->left_ = nullptr;
    this->right_ = nullptr;
}


MerkleNode::MerkleNode(std::shared_ptr<MerkleNode> val){
    this->curr_ = val;
    this->hash_ = val->hash_;
    this->left_ = nullptr;
    this->right_ = nullptr;
}

MerkleNode::MerkleNode(std::shared_ptr<MerkleNode> left,std::shared_ptr<MerkleNode> right){
    this->left_ = std::move(left);
    this->right_ = std::move(right); 

    //
    std::string hash;
    if(this->left_)
        hash.append(this->left_->Hash());
    
    if(this->right_)
        hash.append(this->right_->Hash());

    this->value_ = hash;
    this->hash_ = this->ComputeHash();
}


MerkleNode::~MerkleNode(){
}

std::shared_ptr<MerkleNode> MerkleNode::Left(){
    return left_;
}

std::shared_ptr<MerkleNode> MerkleNode::Right(){
    return right_;
}

bool MerkleNode::HasChildren(){
    return left_ || right_;
}

std::string MerkleNode::Hash(){
    return hash_;    
}

std::shared_ptr<MerkleNode> MerkleNode::MerkleTree(std::vector<std::string> data){
    std::vector<std::shared_ptr<MerkleNode>> payload;
    for(auto& datum: data){
        auto node = std::make_shared<MerkleNode>(datum);
        payload.push_back(node);
        
    }
    
    return MerkleTree(payload);
}

std::shared_ptr<MerkleNode> MerkleNode::MerkleTree(std::vector<std::shared_ptr<MerkleNode>> nodes){
    if(nodes.size() == 1){
        return std::make_shared<MerkleNode>(nodes[0]);
    }
    if(nodes.size() ==2){
        return std::make_shared<MerkleNode>(nodes[0],nodes[1]);
    }

    std::vector<std::shared_ptr<MerkleNode>> left;
    std::vector<std::shared_ptr<MerkleNode>> right;

    size_t half = (nodes.size()%2)==0 ? nodes.size()/2 : nodes.size()/2 +1;

    std::for_each(nodes.begin(),nodes.begin()+half,[&](std::shared_ptr<MerkleNode> node){
        left.push_back(node);
    });
    
    std::for_each(nodes.begin()+half,nodes.end(),[&](std::shared_ptr<MerkleNode> node){
        right.push_back(node);
    });

    return std::make_shared<MerkleNode>(MerkleTree(left),MerkleTree(right));

}


std::string MerkleNode::ComputeHash(){
    CryptoPP::SHA256 hash_func;
    std::string hash;
    CryptoPP::StringSource src(this->value_,true,new CryptoPP::HashFilter(hash_func,new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
    return hash;
}

bool MerkleNode::Validate(){
    if(this->left_ && !this->left_->Validate()){
        return false;
    }
    if(this->right_ && this->right_->Validate()){
        return false;
    }
    std::string hash = this->ComputeHash();
    // std::cout<<hash<<std::endl;
    return hash == this->hash_;
}