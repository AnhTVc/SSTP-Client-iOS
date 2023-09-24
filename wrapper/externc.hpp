//
//  externc.hpp
//  OpenConnectNew
//
//  Created by Tran Viet Anh on 4/10/18.
//  Copyright © 2018 NextVPN Corporation. All rights reserved.
//

#ifndef externc_hpp
#define externc_hpp
//#include "openconnect.h"
#include <stdio.h>
#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

//typedef void* mylibrary_mytype_t;
EXTERNC int test_externc(struct oc_ip_info *info_ip, void *tb);
//EXTERNC void mylibrary_mytype_destroy(mylibrary_mytype_t mytype);
//EXTERNC void mylibrary_mytype_doit(mylibrary_mytype_t self, int param);

#undef EXTERNC
#endif /* externc_hpp */
