#ifndef EXCEPTIONS_HPP
#define EXCEPTIONS_HPP

#include <exception>
#include <string>

using namespace std;
class MSGPACK_FAIL : public exception{
    string msg;
    public:
    
        MSGPACK_FAIL(string msg):msg(msg){}
        virtual const char* what() const throw(){
            return msg.c_str();
        }

};

#endif