#include "blockchain/merkle.hpp"
#include <iostream>

int main(){
    std::vector<std::string> elem{"A","B","C","D"};
    auto tree = MerkleNode::MerkleTree(elem);
    
    tree->Validate();
    std::cout<<"OUTPUT:"<<std::endl<<std::endl;

    std::cout<<tree->Hash()<<std::endl<<std::endl;

    std::cout<<tree->Left()->Hash()<<std::endl<<std::endl;;

    std::cout<<tree->Left()->Left()->Hash()<<std::endl;
    // std::cout<<tree->Left()->Left()->Left()->Hash()<<std::endl;
    // std::cout<<tree->Left()->Left()->Right()->Hash()<<std::endl;
    std::cout<<tree->Left()->Right()->Hash()<<std::endl<<std::endl;

    std::cout<<tree->Right()->Hash()<<std::endl;
    std::cout<<tree->Right()->Left()->Hash()<<std::endl;
    std::cout<<tree->Right()->Right()->Hash()<<std::endl;

}