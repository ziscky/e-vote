#ifndef LOG_HPP
#define LOG_HPP

#include <iostream>
#include <string>
#include <mutex>
#include "utils/termcolor.hpp"

using namespace std;


class Logger{
    public:
        Logger(){}
        ~Logger(){}

        template <typename T,typename... Ts>
        void Debug(T,Ts...);

        template <typename T,typename... Ts>
        void Error(T,Ts...);

        template <typename T,typename... Ts>
        void Info(T,Ts...);

    private:
        bool mDebug = true;
        bool mDI = true;
        bool mError = true;
        bool mDE = true;
        bool mInfo = true;
        bool mDII = true;

        std::mutex mMutex;
        void Debug(){cout<<endl;mDI = true;};
        void Error(){cout<<endl;mDE = true;};
        void Info(){cout<<endl;mDII = true;};
};

template <typename T,typename... Ts>
void Logger::Debug(T var1,Ts... var2){
    
    if (mDebug){
        if (mDI){
            lock_guard<mutex> lck(mMutex);
            cout<<termcolor::blue<<"[DEBUG]:"<<var1;
            mDI = false;
        }else{
            cout<<var1;
        }
        this->Debug(var2...);
    }
}

template <typename T,typename... Ts>
void Logger::Error(T var1,Ts... var2){
    if(mError){
        if (mDE){
            lock_guard<mutex> lck(mMutex);
            cerr<<termcolor::red<<"[ERROR]:"<<var1;
            mDE = false;
        }else{
            cerr<<var1;
        }
        this->Error(var2...);
    }
}

template <typename T,typename... Ts>
void Logger::Info(T var1,Ts... var2){
    if(mInfo){
        if(mDII){
            lock_guard<mutex> lck(mMutex);
            cout<<termcolor::green<<"[INFO]:"<<var1;
            mDII = false;
        }else{
            cout<<var1;
        }
        this->Info(var2...);
    }
}

#endif
