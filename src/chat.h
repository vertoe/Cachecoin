/* 
 * File:   CChat.h
 * Author: kalgecin
 *
 * Created on May 27, 2014, 12:05 PM
 */
#include <iostream>

#include "protocol.h"
using namespace std;
#ifndef CCHAT_H
#define	CCHAT_H

class CChat {
public:
    
    CChat();
    CChat(int64 s, int64 r);
    CChat(const CChat& orig);
    void encryptMessage();
    void setMessage(string msg);
    bool isEncrypted();
    string getMessage();
    int64 getReceiver();
    int64 getSender();
    void decrypt(int64 privKey);
    bool relayTo(CNode* pnode);
    virtual ~CChat();
private:
    //sender addr
    int64 sender;
    //receipient addr
    int64 receiver;
    string message;
    bool encrypted;
};

#endif	/* CCHAT_H */

