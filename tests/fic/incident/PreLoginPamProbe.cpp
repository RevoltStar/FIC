// VM-only probe: run the real installed controlled account stack, never auth.
#include <security/pam_appl.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include <iostream>
int main(int argc,char** argv) {
    std::ifstream dmi("/sys/class/dmi/id/product_name"); std::string product;std::getline(dmi,product);
    if(argc!=3 || geteuid()!=0 || product!="FIC-Prelogin-Disposable" ||
        access("/etc/fic-prelogin-test-vm",F_OK)!=0) return 2;
    pam_handle_t* handle=nullptr;
    const pam_conv conversation{[](int,const pam_message**,pam_response**,void*){return PAM_CONV_ERR;},nullptr};
    int result=pam_start(argv[1],argv[2],&conversation,&handle);
    if(result==PAM_SUCCESS) result=pam_acct_mgmt(handle,0);
    std::cout<<"account_result="<<result<<'\n';
    if(handle)pam_end(handle,result);
    return result==PAM_SUCCESS?0:1;
}
