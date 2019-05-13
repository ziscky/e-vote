#ifndef UTILS_HPP
#define UTILS_HPP

#include "msgpack.hpp"
#include "json.hpp"
#include "exceptions.hpp"
#include <string>
#include <vector>
#include <initializer_list>

namespace utils{

msgpack::object* findMapValue(const msgpack::object& map, const std::string& key);
std::vector<uint8_t> unpackBlob(const msgpack::object& o);
nlohmann::json msgPackToJson(const char* data,size_t size);
void splitString(const string& s, char c,vector<string>& v);
bool checkParams(const nlohmann::json& j,std::initializer_list<string> keys);





}

#endif