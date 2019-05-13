#include "utils.hpp"

namespace utils{
//retrieves a msgpack object from a key-value masgpack map.
msgpack::object* findMapValue(const msgpack::object& map, const std::string& key) {
    if (map.type != msgpack::type::MAP) throw msgpack::type_error();
    for (unsigned i = 0; i < map.via.map.size; i++) {
        auto& o = map.via.map.ptr[i];
        //make sure the key is a string and check of the map value is registered with the provided key as a string.
        if (o.key.type == msgpack::type::STR && o.key.as<std::string>() == key)
            return &o.val;
    }
    return nullptr;
}


//converts a msgpack object to a vector of unsigned ints(blob)
std::vector<uint8_t> unpackBlob(const msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::BIN:
        return {o.via.bin.ptr, o.via.bin.ptr+o.via.bin.size};
    case msgpack::type::STR:
        return {o.via.str.ptr, o.via.str.ptr+o.via.str.size};
    case msgpack::type::ARRAY: {
        std::vector<uint8_t> ret(o.via.array.size);
        
        //convert all msgpack objects in the array to a vector of uint8_ts(blobs)
        std::transform(o.via.array.ptr, o.via.array.ptr+o.via.array.size, ret.begin(), [](const msgpack::object& b) {
            return b.as<uint8_t>();
        });
        return ret;
    }
    default:
        throw msgpack::type_error();
    }
}


//converts a msgpack formatted blob to a JSON object
nlohmann::json msgPackToJson(const char* data,size_t size){
    //{"id":0,"dat":{"body":{"type":0,"data":"TEXT"}}}
    auto obj = msgpack::v3::unpack( data, size);
    if(obj->is_nil()){
        throw new MSGPACK_FAIL("Couldn't unpack object");
    }

    if(obj->type != msgpack::type::MAP){
        //unsupported
        throw new MSGPACK_FAIL("Object not a MAP");;
    }

    auto payload_blob = utils::findMapValue(obj.get(),"dat");
    if(payload_blob->is_nil()){
        throw new MSGPACK_FAIL("'dat' key does not exist");
    }
    if(payload_blob->type != msgpack::type::MAP){
        //unsupported
        throw new MSGPACK_FAIL("'dat' object not a MAP");  
    }
    
    payload_blob = utils::findMapValue(*payload_blob,"body");
    if(payload_blob->is_nil()){
        throw new MSGPACK_FAIL("'body' key does not exist");
    }
    if(payload_blob->type != msgpack::type::MAP){
        //unsupported
        throw new MSGPACK_FAIL("'body' object not a MAP");  
    }
    
    auto data_blob = utils::findMapValue(*payload_blob,"data");
    if(data_blob == nullptr){
        throw new MSGPACK_FAIL("'data' key does not exist");  
    }
    
    std::vector<uint8_t> data_ = utils::unpackBlob(*data_blob);
    std::string data_str{data_.begin(),data_.end()};

    return nlohmann::json::parse(data_str);
    
}

void splitString(const string& s, char c,vector<string>& v) {
   size_t i = 0;
   size_t j = s.find(c); // position of delimiter

   while (j != string::npos) {
      v.push_back(s.substr(i, j-i));
      i = ++j;
      j = s.find(c, j);

      if (j == string::npos)
         v.push_back(s.substr(i, s.length()));
   }
}

bool checkParams(const nlohmann::json& j,std::initializer_list<string> keys){
    for(auto& key: keys){
        if(j[key].is_null()){
            return false;
        }
    }
    return true;
    
}
}