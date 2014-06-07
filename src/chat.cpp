/* 
 * File:   CChat.cpp
 * Author: kalgecin
 * 
 * Created on May 27, 2014, 12:05 PM
 */

#include "chat.h"

CChat::CChat(int64 s, int64 r) {
    sender = s;
    receiver = r;
    message = "";
    encrypted = false;
}
CChat::CChat() {
    sender = 0;
    receiver = 0;
    message = "";
    encrypted = false;
}

CChat::CChat(const CChat& orig) {
}

CChat::~CChat() {
}

void CChat::setMessage(string msg) {
    message = msg;
}

string CChat::getMessage() {
    return message;
}

void CChat::encryptMessage() {
    //TODO: make encryption
    encrypted = true;
    
}

bool CChat::isEncrypted() {
    return encrypted;
}

int64 CChat::getReceiver() {
    return receiver;
}

int64 CChat::getSender() {
    return sender;
}

void CChat::decrypt(int64 privKey) {
    if(encrypted){
        //TODO: decryption
        encrypted = false;
    }
}

bool CChat::relayTo(CNode* pnode) {
    //TODO: only relay if this is the first time we see this;
    pnode->PushMessage("alert", *this);
    return true;
}
