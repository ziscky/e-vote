#include<memory>
#include<string>
#include<vector>
#include<algorithm>

class MerkleNode{
    private:
        std::shared_ptr<MerkleNode> left_;
        std::shared_ptr<MerkleNode> right_;
        std::shared_ptr<MerkleNode> curr_;

        std::string hash_;
        std::string value_;
        std::string ComputeHash();

    public:
        MerkleNode(std::string val);
        MerkleNode(std::shared_ptr<MerkleNode> val);
        MerkleNode(std::shared_ptr<MerkleNode> left,std::shared_ptr<MerkleNode> right);
        ~MerkleNode();
        
        std::shared_ptr<MerkleNode> Left();
        std::shared_ptr<MerkleNode> Right();
        std::string Hash();
        bool HasChildren();
        bool Validate();


        
        static std::shared_ptr<MerkleNode> MerkleTree(std::vector<std::shared_ptr<MerkleNode>> nodes);
        static std::shared_ptr<MerkleNode> MerkleTree(std::vector<std::string> data);

};