//
// Copyright (C) 2011 David Eckhoff <eckhoff@cs.fau.de>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "veins/modules/application/ieee80211p/BaseWaveApplLayer.h"

const simsignalwrap_t BaseWaveApplLayer::mobilityStateChangedSignal = simsignalwrap_t(MIXIM_SIGNAL_MOBILITY_CHANGE_NAME);
const simsignalwrap_t BaseWaveApplLayer::parkingStateChangedSignal = simsignalwrap_t(TRACI_SIGNAL_PARKING_CHANGE_NAME);
int BaseWaveApplLayer::counter = 1;
int BaseWaveApplLayer::startPSID = 21000000;
//double BaseWaveApplLayer::totalDuration = 0.0;
//int BaseWaveApplLayer::totalBSMs = 0;

void BaseWaveApplLayer::initialize(int stage) {
    BaseApplLayer::initialize(stage);

    if (stage==0) {

        //initialize pointers to other modules
        if (FindModule<TraCIMobility*>::findSubModule(getParentModule())) {
            mobility = TraCIMobilityAccess().get(getParentModule());
            traci = mobility->getCommandInterface();
            traciVehicle = mobility->getVehicleCommandInterface();
        }
        else {
            traci = NULL;
            mobility = NULL;
            traciVehicle = NULL;
        }

        annotations = AnnotationManagerAccess().getIfExists();
        ASSERT(annotations);

        mac = FindModule<WaveAppToMac1609_4Interface*>::findSubModule(
                getParentModule());
        assert(mac);

        myId = getParentModule()->getId();

        //set up PKI parameters
        AutoSeededRandomPool prng;
        int i = ++counter;
        do{
            //std::cout<<"counter is: "<<i<<std::endl;
            skey = skeyV.at(i);
            pkey = pkeyV.at(i);
        }while(false);

        //ECDSA<ECP, SHA256>::Signer signer(skey);
        //ECDSA<ECP, SHA256>::Verifier verifier(pkey);

        certificate.pkeyVehicle = pkey;
        std::string fileName = "/home/sonia/temporary/signPK" + std::to_string(i+1) + ".dat";
        ifstream rfile (fileName, ios::in|ios::binary);
        std::string buffer ;
        getline(rfile, buffer);
        certificate.signature = buffer;
        getline(rfile, buffer);
        certificate.signature = certificate.signature + "\n" + buffer;
        getline(rfile, buffer);
        certificate.signature = certificate.signature + "\n" + buffer;
        certificate.signature.resize(64);

        /*ECDSA<ECP, SHA256>::PublicKey publickeyCA = certificate.pkeyVehicle;
        const ECP::Point& q = publickeyCA.GetPublicElement();
        ECDSA<ECP, SHA256>::Verifier verifier1(pkeyCA);
        std::cout<<"Works till here"<<std::endl;
        const Integer& qx = q.x;
        const Integer& qy = q.y;
        std::stringstream ss;
        ss << std::hex<<qx;
        std::string msg = ss.str();

        std::string signature(64, 0x00);
        signature = certificate.signature;
        std::cout<<"Message TraCI: "<<msg<<std::endl;
        std::cout<<"Certificates: "<<signature<<std::endl;
        bool result = verifier1.VerifyMessage( (const byte*)&msg[0], msg.size(), (const byte*)signature[0], signature.size());
        */
        /*const ECP::Point& q = certificate.pkeyVehicle.GetPublicElement();
        ECDSA<ECP, SHA256>::Verifier verifier1(pkeyCA);
        const Integer& qx = q.x;
        const Integer& qy = q.y;
        std::stringstream ss;
        ss << std::hex<<qx;
        std::string msg = ss.str();

        std::cout<<"opening file "<<fileName<<std::endl;
        std::cout<<"Message: "<<msg<<std::endl;
        std::cout<<"Certificates: "<<certificate.signature<<std::endl;
        //std::cout<<"Msg: "<<msg<<std::endl;
        bool result = verifier1.VerifyMessage( (const byte*)&msg[0], msg.size(), (const byte*)&certificate.signature[0], certificate.signature.size() );
        if(result){
            std::cout<<"Validated successfully"<<std::endl;
        }
        else
        {
            //std::cout<<"Validated unsuccessfully"<<std::endl;
            //std::cout<<"MSG : "<<msg<<std::endl;
            //std::cout<<"Sig : "<<signature<<std::endl;
            //std::cout<<"Msg size : "<<msg.size()<<std::endl;
            std::cout<<"Validated unsuccessfully"<<std::endl;
        }*/
        //read parameters
        headerLength = par("headerLength").longValue();
        sendBeacons = par("sendBeacons").boolValue();
        beaconLengthBits = par("beaconLengthBits").longValue();
        beaconUserPriority = par("beaconUserPriority").longValue();
        beaconInterval =  par("beaconInterval");

        dataLengthBits = par("dataLengthBits").longValue();
        dataOnSch = par("dataOnSch").boolValue();
        dataUserPriority = par("dataUserPriority").longValue();

        wsaInterval = par("wsaInterval").doubleValue();
        communicateWhileParked = par("communicateWhileParked").boolValue();
        currentOfferedServiceId = -1;

        isParked = false;


        findHost()->subscribe(mobilityStateChangedSignal, this);
        findHost()->subscribe(parkingStateChangedSignal, this);

        sendBeaconEvt = new cMessage("beacon evt", SEND_BEACON_EVT);
        sendWSAEvt = new cMessage("wsa evt", SEND_WSA_EVT);

        generatedBSMs = 0;
        generatedWSAs = 0;
        generatedWSMs = 0;
        receivedBSMs = 0;
        receivedWSAs = 0;
        receivedWSMs = 0;
    }
    else if (stage == 1) {
        //simulate asynchronous channel access

        if (dataOnSch == true && !mac->isChannelSwitchingActive()) {
            dataOnSch = false;
            std::cerr << "App wants to send data on SCH but MAC doesn't use any SCH. Sending all data on CCH" << std::endl;
        }
        simtime_t firstBeacon = simTime();

        if (par("avoidBeaconSynchronization").boolValue() == true) {

            simtime_t randomOffset = dblrand() * beaconInterval;
            firstBeacon = simTime() + randomOffset;

            if (mac->isChannelSwitchingActive() == true) {
                if ( beaconInterval.raw() % (mac->getSwitchingInterval().raw()*2)) {
                    std::cerr << "The beacon interval (" << beaconInterval << ") is smaller than or not a multiple of  one synchronization interval (" << 2*mac->getSwitchingInterval() << "). "
                            << "This means that beacons are generated during SCH intervals" << std::endl;
                }
                firstBeacon = computeAsynchronousSendingTime(beaconInterval, type_CCH);
            }

            if (sendBeacons) {
                scheduleAt(firstBeacon, sendBeaconEvt);
            }
        }
    }
}

simtime_t BaseWaveApplLayer::computeAsynchronousSendingTime(simtime_t interval, t_channel chan) {

    /*
     * avoid that periodic messages for one channel type are scheduled in the other channel interval
     * when alternate access is enabled in the MAC
     */

    simtime_t randomOffset = dblrand() * beaconInterval;
    simtime_t firstEvent;
    simtime_t switchingInterval = mac->getSwitchingInterval(); //usually 0.050s
    simtime_t nextCCH;

    /*
     * start event earliest in next CCH (or SCH) interval. For alignment, first find the next CCH interval
     * To find out next CCH, go back to start of current interval and add two or one intervals
     * depending on type of current interval
     */

    if (mac->isCurrentChannelCCH()) {
        nextCCH = simTime() - SimTime().setRaw(simTime().raw() % switchingInterval.raw()) + switchingInterval*2;
    }
    else {
        nextCCH = simTime() - SimTime().setRaw(simTime().raw() %switchingInterval.raw()) + switchingInterval;
    }

    firstEvent = nextCCH + randomOffset;

    //check if firstEvent lies within the correct interval and, if not, move to previous interval

    if (firstEvent.raw()  % (2*switchingInterval.raw()) > switchingInterval.raw()) {
        //firstEvent is within a sch interval
        if (chan == type_CCH) firstEvent -= switchingInterval;
    }
    else {
        //firstEvent is within a cch interval, so adjust for SCH messages
        if (chan == type_SCH) firstEvent += switchingInterval;
    }

    return firstEvent;
}

void BaseWaveApplLayer::populateWSM(WaveShortMessage* wsm, int rcvId, int serial) {



    wsm->setWsmVersion(1);
    wsm->setTimestamp(simTime());
    wsm->setSenderAddress(myId);
    wsm->setRecipientAddress(rcvId);
    wsm->setSerial(serial);
    wsm->setBitLength(headerLength);


    if (BasicSafetyMessage* bsm = dynamic_cast<BasicSafetyMessage*>(wsm) ) {
        bsm->setSenderPos(curPosition);
        bsm->setSenderPos(curPosition);
        bsm->setSenderSpeed(curSpeed);
        bsm->setPsid(-1);
        bsm->setChannelNumber(Channels::CCH);
        bsm->addBitLength(beaconLengthBits);
        bsm->setCertificateV(certificate.pkeyVehicle, certificate.signature);
        wsm->setUserPriority(beaconUserPriority);

        AutoSeededRandomPool prng;
        ECDSA<ECP, SHA256>::Signer signer(skey);
        ECDSA<ECP, SHA256>::Verifier verifier(pkey);
        size_t siglen = signer.MaxSignatureLength();
        std::string msg = bsm->getWsmData();
        std::string timestamp = bsm->getTimestamp().str();
        msg.append(timestamp);
        std::string signature(siglen, 0x00);
        siglen = signer.SignMessage( prng, (const byte*)&msg[0], msg.size(), (byte*)&signature[0] );
        signature.resize(siglen);
        bsm->setMsgSignature(signature);

    }
    else if (WaveServiceAdvertisment* wsa = dynamic_cast<WaveServiceAdvertisment*>(wsm)) {
        wsa->setChannelNumber(Channels::CCH);
        wsa->setTargetChannel(currentServiceChannel);
        wsa->setPsid(currentOfferedServiceId);
        wsa->setServiceDescription(currentServiceDescription.c_str());
    }
    else {
        if (dataOnSch) wsm->setChannelNumber(Channels::SCH1); //will be rewritten at Mac1609_4 to actual Service Channel. This is just so no controlInfo is needed
        else wsm->setChannelNumber(Channels::CCH);
        wsm->addBitLength(dataLengthBits);
        wsm->setUserPriority(dataUserPriority);
    }
}

void BaseWaveApplLayer::receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details) {
    Enter_Method_Silent();
    if (signalID == mobilityStateChangedSignal) {
        handlePositionUpdate(obj);
    }
    else if (signalID == parkingStateChangedSignal) {
        handleParkingUpdate(obj);
    }
}

void BaseWaveApplLayer::handlePositionUpdate(cObject* obj) {
    ChannelMobilityPtrType const mobility = check_and_cast<ChannelMobilityPtrType>(obj);
    curPosition = mobility->getCurrentPosition();
    curSpeed = mobility->getCurrentSpeed();
}

void BaseWaveApplLayer::handleParkingUpdate(cObject* obj) {
    //this code should only run when used with TraCI
    isParked = mobility->getParkingState();
    if (communicateWhileParked == false) {
        if (isParked == true) {
            (FindModule<BaseConnectionManager*>::findGlobalModule())->unregisterNic(this->getParentModule()->getSubmodule("nic"));
        }
        else {
            Coord pos = mobility->getCurrentPosition();
            (FindModule<BaseConnectionManager*>::findGlobalModule())->registerNic(this->getParentModule()->getSubmodule("nic"), (ChannelAccess*) this->getParentModule()->getSubmodule("nic")->getSubmodule("phy80211p"), &pos);
        }
    }
}

void BaseWaveApplLayer::handleLowerMsg(cMessage* msg) {

    WaveShortMessage* wsm = dynamic_cast<WaveShortMessage*>(msg);
    ASSERT(wsm);

    if (BasicSafetyMessage* bsm = dynamic_cast<BasicSafetyMessage*>(wsm)) {
        receivedBSMs++;
        onBSM(bsm);
    }
    else if (WaveServiceAdvertisment* wsa = dynamic_cast<WaveServiceAdvertisment*>(wsm)) {
        receivedWSAs++;
        onWSA(wsa);
    }
    else {
        receivedWSMs++;
        onWSM(wsm);
    }

    delete(msg);
}

void BaseWaveApplLayer::handleSelfMsg(cMessage* msg) {
    switch (msg->getKind()) {
    case SEND_BEACON_EVT: {
        BasicSafetyMessage* bsm = new BasicSafetyMessage();
        populateWSM(bsm);
        sendDown(bsm);
        scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
        break;
    }
    case SEND_WSA_EVT:   {
        WaveServiceAdvertisment* wsa = new WaveServiceAdvertisment();
        populateWSM(wsa);
        sendDown(wsa);
        scheduleAt(simTime() + wsaInterval, sendWSAEvt);
        break;
    }
    default: {
        if (msg)
            DBG_APP << "APP: Error: Got Self Message of unknown kind! Name: " << msg->getName() << endl;
        break;
    }
    }
}

void BaseWaveApplLayer::finish() {
    recordScalar("generatedWSMs",generatedWSMs);
    recordScalar("receivedWSMs",receivedWSMs);

    recordScalar("generatedBSMs",generatedBSMs);
    recordScalar("receivedBSMs",receivedBSMs);

    recordScalar("generatedWSAs",generatedWSAs);
    recordScalar("receivedWSAs",receivedWSAs);
}

BaseWaveApplLayer::~BaseWaveApplLayer() {
    cancelAndDelete(sendBeaconEvt);
    cancelAndDelete(sendWSAEvt);
    findHost()->unsubscribe(mobilityStateChangedSignal, this);
}

void BaseWaveApplLayer::startService(Channels::ChannelNumber channel, int serviceId, std::string serviceDescription) {
    if (sendWSAEvt->isScheduled()) {
        error("Starting service although another service was already started");
    }

    mac->changeServiceChannel(channel);
    currentOfferedServiceId = serviceId;
    currentServiceChannel = channel;
    currentServiceDescription = serviceDescription;

    simtime_t wsaTime = computeAsynchronousSendingTime(wsaInterval, type_CCH);
    scheduleAt(wsaTime, sendWSAEvt);

}

void BaseWaveApplLayer::stopService() {
    cancelEvent(sendWSAEvt);
    currentOfferedServiceId = -1;
}

void BaseWaveApplLayer::sendDown(cMessage* msg) {
    checkAndTrackPacket(msg);
    BaseApplLayer::sendDown(msg);
}

void BaseWaveApplLayer::sendDelayedDown(cMessage* msg, simtime_t delay) {
    checkAndTrackPacket(msg);
    BaseApplLayer::sendDelayedDown(msg, delay);
}

void BaseWaveApplLayer::checkAndTrackPacket(cMessage* msg) {
    if (isParked && !communicateWhileParked) error("Attempted to transmit a message while parked, but this is forbidden by current configuration");

    if (dynamic_cast<BasicSafetyMessage*>(msg)) {
        DBG_APP << "sending down a BSM" << std::endl;
        generatedBSMs++;
    }
    else if (dynamic_cast<WaveServiceAdvertisment*>(msg)) {
        DBG_APP << "sending down a WSA" << std::endl;
        generatedWSAs++;
    }
    else if (dynamic_cast<WaveShortMessage*>(msg)) {
        DBG_APP << "sending down a wsm" << std::endl;
        generatedWSMs++;
    }
}

bool BaseWaveApplLayer::verifyPKSignature(BasicSafetyMessage* bsm) {

    ECDSA<ECP, SHA256>::PublicKey publicKey = bsm->getCertPublicKey();
    const ECP::Point& q = publicKey.GetPublicElement();
    ECDSA<ECP, SHA256>::Verifier verifier1(pkeyCA);
    const Integer& qx = q.x;
    const Integer& qy = q.y;
    std::stringstream ss;
    ss << std::hex<<qx;
    std::string pKCA = ss.str();

    std::string signature(64, 0x00);
    signature = bsm->getCertSignature();

    bool result1 = verifier1.VerifyMessage( (const byte*)&pKCA[0], pKCA.size(), (const byte*)&bsm->getCertSignature()[0], bsm->getCertSignature().size() );

    ECDSA<ECP, SHA256>::Verifier verifier2(publicKey);
    std::string msg = bsm->getWsmData();
    std::string timestamp = bsm->getTimestamp().str();
    msg = msg.append(timestamp);
    bool result2 = verifier2.VerifyMessage( (const byte*)&msg[0], msg.size(), (const byte*)&bsm->getMsgSignature()[0], bsm->getMsgSignature().size() );

    return (result1 & result2);
}

/*void BaseWaveApplLayer::printStat(){
    std::cout<<"Total Duration is: "<<totalDuration<<std::endl;
    std::cout<<"Total BSMs are: "<<totalBSMs<<std::endl;
}*/

int BaseWaveApplLayer::getBSMSize(BasicSafetyMessage* bsm) {
    return ((int)bsm->getMsgSignature().size()+certificate.signature.size()+65+(int)bsm->getByteLength());
}
