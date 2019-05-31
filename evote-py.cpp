//
// Created by emok on 5/31/19.
//

#include <Python.h>
#include <boost/python.hpp>
#include "security/identity.hpp"
#include <string>

using namespace boost::python;


BOOST_PYTHON_MODULE(evotepy){
    class_<Identity,boost::noncopyable>("Identity",init<const std::string&>())
            .def("Sign",&Identity::SignData)
            .def("Decrypt",&Identity::DecryptData)
            .def("ComputeHash",&Identity::ComputeHash)
            .def("IESPublicKey",&Identity::IESPublicKey)
            .def("DSAPublicKey",&Identity::DSAPublicKey)
            .def("Verify", static_cast<bool(Identity::*)(const std::string&,const std::string&)>(&Identity::VerifyData))
            .def("Verify", static_cast<bool(Identity::*)(const std::string&,const std::string&,const std::string&)>(&Identity::VerifyData))
            .def("Encrypt", static_cast<std::string(Identity::*)(const std::string&,const std::string&)>(&Identity::EncryptData))
            .def("Encrypt", static_cast<std::string(Identity::*)(const std::string&)>(&Identity::EncryptData));
}