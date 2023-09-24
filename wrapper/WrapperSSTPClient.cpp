//
//  WrapperSSTPClient.cpp
//  sstp-ios
//
//  Created by Anh Viet on 20/09/2023.
//

#include "WrapperSSTPClient.hpp"
namespace SSTPClientNameSpace {
    namespace ClientAPI {
    
        int OpenClient::connect(){
            // 1.
            //this->tun_builder_establish();
    //        main_openconnect(argc, argv, this, pass);

            return 0;
        }
            
        int OpenClient::disconnect(){
            disconnect();
            return 0;
        }
    }
}
