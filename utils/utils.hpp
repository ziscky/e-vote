#include "msgpack.hpp"
#include "json.hpp"
#include "exceptions.hpp"
#include <string>
#include <vector>

namespace utils{

msgpack::object* findMapValue(const msgpack::object& map, const std::string& key) {
    if (map.type != msgpack::type::MAP) throw msgpack::type_error();
    for (unsigned i = 0; i < map.via.map.size; i++) {
        auto& o = map.via.map.ptr[i];
        if (o.key.type == msgpack::type::STR && o.key.as<std::string>() == key)
            return &o.val;
    }
    return nullptr;
}


std::vector<uint8_t> unpackBlob(const msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::BIN:
        return {o.via.bin.ptr, o.via.bin.ptr+o.via.bin.size};
    case msgpack::type::STR:
        return {o.via.str.ptr, o.via.str.ptr+o.via.str.size};
    case msgpack::type::ARRAY: {
        std::vector<uint8_t> ret(o.via.array.size);
        std::transform(o.via.array.ptr, o.via.array.ptr+o.via.array.size, ret.begin(), [](const msgpack::object& b) {
            return b.as<uint8_t>();
        });
        return ret;
    }
    default:
        throw msgpack::type_error();
    }
}


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

}
