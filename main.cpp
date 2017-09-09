//
// Created by LupusAnay on 06.08.17.
//

#include <iostream>
#include "PcapSession.h"

using namespace std;

int main(int argc, char *argv[]){
    // If not provided device name
    if(argv[1] == nullptr) {
        cout << "Please, provide program argument with device name: ";
        return 2;
    }
    else {
        PcapSession session = PcapSession();
        session.startSession("", argv[1], 10); //const char *filter, char *device_name, unsigned int packet_count
        session.closeSession();
    }
    return 0;
}