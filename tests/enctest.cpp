#include "security/identity.hpp"
#include "security/ecc.hpp"

#include <iostream>
#include <string>



int main(){
    KeyGen<HexKeyPair> keygen(true);
    while(true){
        std::cout<<"enter key: ";
        char key[100];
        std::cin>>key;
        
        // keygen.test();
        std::string kstr(key);
        std::cout<<std::endl<<"Setting key: "<<kstr<<std::endl;
        auto keys = keygen.GenerateKeys(kstr);
        std::cout<<keys;
        auto initKeys = keygen.LoadKeys(keys);
        auto v = keygen.TestDSKeys(initKeys);
        if(v){
            std::cout<<"Keys are valid"<<std::endl;
        }
    }

    Identity iden(  "03014E34831D17542746C690113C25E3A0ADA1CA79C1C4599B2CD1C5CB1991E576DB57310927AC902D314ED96A0FD525F444D07DE8E36049BE2DE838FC274BEA3942C7",
                    "0189B4B36CC98E3DF466450FAC75E10810FCA842B135C928CDAC31227D82653AA786B64B62279C58E039A49E3C70DBFFD157A981E30E6695F68621CE7FE5E9EF7822"  ,
                    "03019B384C1DA0E57EA6CE0519FB5CEE3B7869ED19F069B4731B074460AB2059C78FF5B3015DDAAA68464101A4A5CC25B99185CF9CED931AF84C1DC0222B54DF519934",
                    "281F65709865ED2944CF498208B8D7AF1D416478484CED4382C8E856E55E79050EB8EC8EB0D9394FA273F76054B74D1AB0CF18FF6A1BE85423457DE4C932D98A29");

    std::string t("DATA");
    auto sig = iden.SignData(t);
    std::cout<<sig<<std::endl;
    std::cout<<iden.VerifyData(t,sig)<<std::endl;
    
    auto ciph = iden.EncryptData(t);
    std::cout<<ciph<<std::endl;
    auto dec = iden.DecryptData("04015EE00369CFD3478A26B6794E5D0BD771B0AD777783A46F2E034C307AA3526CDA7C18CA37A69622012C460B7BB56F05699B5475B5B35ECD7E0D49D4A3A36996B66800B17252A5A4BE97FC32E89B8D4BE93F440ACA2452D8798034BD77E14A1511F99FA693B32A37CDA1F35D9973B0E64DAD426F980B6A86088A3745C75F4474AA69D30257B02B39ACAF3A3967B2950BEBF19ABE2CF4C3EB3F1FC2C2469D62C4E397E2C8E94822349473DF946AC4");
    std::cout<<dec<<std::endl;

}