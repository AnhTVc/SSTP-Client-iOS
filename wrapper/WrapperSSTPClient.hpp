//
//  WrapperSSTPClient.hpp
//  sstp-ios
//
//  Created by Anh Viet on 20/09/2023.
//

#ifndef WrapperSSTPClient_hpp
#define WrapperSSTPClient_hpp

#include <stdio.h>

#include "base.h"

namespace SSTPClientNameSpace {
    namespace ClientAPI{
        class OpenClient: public TunBuilderBase{
        public:
            int connect();
            int disconnect();
        };
    };
}

#endif /* WrapperSSTP_h */
