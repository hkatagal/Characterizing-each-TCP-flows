/*
* Authors: Harishkumar Katagal(109915793) & Sagar Basavaraj Dhavali(109929325)
* Program to analyze the wireshark trace and outputs the delay for a DNS query.
* We extended the sample program provided by Prof. Aruna to include the functionality.
* Programing Language: C++
* Input: *.pcap file which has wireshark trace
* Output: Displayed on console and recorded in a output file Output.txt.
*/

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>


using namespace std;

//Structure to store the information about the packet.
//In this case we have used Linked List to store the packet information.
typedef struct packetList{
	int noPacketSender, noByteSender;
	int noPacketRec, noByteRec;
	int noAckSender, noAckRec;
	int larCongWin, avgCongWin;
	int congCount, congFlag, congSize,congTotal;
	int recWinSize,sendWinSize;
	int noOfRetran;
	int oOrderPacket;
	int throughPut, goodPut;
	int lowSendIP, upSendIP;
	int lowRecIP, upRecIP;
	int active;
	int srcPort;
	int seqArr[10000];
	int count;
	int congNew;
	float time,lastTime;
	long int sec, lastSec;
	int scaleFactSend, scaleFactRec;
	int mssRec;
	packetList* nextPacket; //Pointer too next packet in the list
}packetList;


packetList* recordStats(const u_char *packet){
	packetList* temp = new packetList;
	temp->upSendIP = (int)*(packet+26) * 1000;
	temp->upSendIP += (int)*(packet+27);
	temp->lowSendIP = (int)*(packet+28) * 1000;
	temp->lowSendIP += (int)*(packet+29);
	temp->upRecIP = (int)*(packet+30) * 1000;
	temp->upRecIP += (int)*(packet+31);
	temp->lowRecIP = (int)*(packet+32) * 1000;
	temp->lowRecIP += (int)*(packet+33);
	temp->srcPort = (int)*(packet+34)<<8;
	temp->srcPort += (int)*(packet+35);
	temp->nextPacket = NULL;
	temp->scaleFactSend = 1;//<<(*(packet+61));	
	temp->scaleFactRec = 1;
	temp->count=0;
	temp->congFlag=0;
	temp->congCount = 1;
	return(temp);
}

int compareIP(const u_char *packet, packetList* temp1){
	int upSendIP,lowSendIP,upRecIP,lowRecIP,srcPort;
	upSendIP = (int)*(packet+26) * 1000;
	upSendIP += (int)*(packet+27);
	lowSendIP = (int)*(packet+28) * 1000;
	lowSendIP += (int)*(packet+29);
	upRecIP = (int)*(packet+30) * 1000;
	upRecIP += (int)*(packet+31);
	lowRecIP = (int)*(packet+32) * 1000;
	lowRecIP += (int)*(packet+33);
	
	if(upSendIP == temp1->upSendIP && lowSendIP == temp1->lowSendIP){
		if(upRecIP == temp1->upRecIP && lowRecIP == temp1->lowRecIP){
			srcPort = (int)*(packet+34)<<8;
			srcPort += (int)*(packet+35);
			if(srcPort == temp1->srcPort)
				return 1;
		}
	}
	if(upSendIP == temp1->upRecIP && lowSendIP == temp1->lowRecIP){
		if(upRecIP == temp1->upSendIP && lowRecIP == temp1->lowSendIP){
			srcPort = (int)*(packet+36)<<8;
			srcPort += (int)*(packet+37);
			if(srcPort == temp1->srcPort)
				return 2;
		}
	}
	return 3;	
}

int main(int argc, char **argv) 
{
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // A pointer to the packet
	packetList* head = NULL; //Head of the Linked List
	ofstream opFile;	//Pointer to the output file
	int ipHigh=0,ipLow=0;
	int tempNextSeq=0;
	long int nextSeq=0;
	
    //check command line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [pcap file]\n", argv[0]);
        exit(1);
    }
  
    //----------------- 
    //open the pcap file 
    pcap_t *handle; 
	
    char errbuf[PCAP_ERRBUF_SIZE]; // we dont really use this, but is as input to the pcap open function
    
    handle = pcap_open_offline(argv[1], errbuf);   //call pcap library to read the file
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
      return(2); 
    }
   
   //Open the output file
   opFile.open("Output.txt");
   if(opFile == NULL)
   {
		cout<<"Error: Cannot open xml file"<<endl;
		return(3);
	}
	while(packet = pcap_next(handle,&header)){
		if(*(packet+47) == 2){
			if(head == NULL){
				head = recordStats(packet);
				head->time = (header).ts.tv_usec;
				head->sec = (header).ts.tv_sec;
			}
			else{
				packetList* temp1 = head;
				while(temp1->nextPacket!=NULL)
					temp1 = temp1->nextPacket;
				temp1->nextPacket = recordStats(packet);
				temp1 = temp1->nextPacket;
				temp1->time = (header).ts.tv_usec;
				temp1->sec = (header).ts.tv_sec;
			}			
		}
		packetList* temp1 = head;
		while(temp1!=NULL){
			int flag = compareIP(packet,temp1);
			//flag=1 --> Sender Packet flag=2 --> Receiver Packet flag=3 no match
			if(temp1->active == 1)
				flag=3;
			if(flag==1){
				temp1->noPacketSender +=1;
				temp1->lastTime = (header).ts.tv_usec;
				temp1->lastSec = (header).ts.tv_sec;
				if((*(packet+47))==16)
					temp1->noAckSender+=1;
				if(temp1->congFlag==1){
					if(temp1->larCongWin < temp1->congSize)
						temp1->larCongWin = temp1->congSize;
					int congTemp;
					if(temp1->congNew > 2190)
						congTemp = 2;
					else if(temp1->congNew > 1095)
						congTemp = 3;
					else if(temp1->congNew <= 1095)
						congTemp = 4;
					temp1->congTotal += congTemp;
					if(temp1->larCongWin < congTemp)
						temp1->larCongWin = congTemp;
					temp1->congSize = 0;
					temp1->congFlag = 0;
					
				}
				temp1->noByteSender += header.len-34-((int)(*(packet+46))/4);
				temp1->throughPut += header.len;
				int winSize = *(packet+48) << 8;
				winSize += *(packet+49);
				temp1->sendWinSize +=(winSize*temp1->scaleFactSend);
				if(*(packet+47) == 2){
					temp1->scaleFactSend = 1<<(*(packet+61));	
					
				}
				break;
			}
			else if(flag==2){
				if(*(packet+47)==18){
					temp1->mssRec = (*(packet+56)<<8);
					temp1->mssRec += *(packet+57);
					if(temp1->mssRec > 2190)
						temp1->congSize = 2;
					else if(temp1->mssRec > 1095)
						temp1->congSize = 3;
					else if(temp1->mssRec <= 1095)
						temp1->congSize = 4;
					temp1->congFlag=1;
					temp1->congTotal += temp1->congSize;
				}
				temp1->noPacketRec +=1;
				temp1->lastTime = (header).ts.tv_usec;
				temp1->lastSec = (header).ts.tv_sec;
				if(*(packet+47)==16)
					temp1->noAckRec+=1;
				int byteData = header.len-34-((int)(*(packet+46))/4);
				temp1->noByteRec += byteData;
				temp1->throughPut += header.len;
				if(byteData>0){
				
					//Congestion Window Logic
					if(!temp1->congFlag)
						temp1->congCount++;
					temp1->congFlag = 1;
					
					temp1->congNew+=byteData;
					
					long int seqTemp = (int)*(packet+38);
					for(int i=39;i<=41;i++){
						seqTemp = seqTemp<<8;
						seqTemp += (int)*(packet+i);
					}
					
					if((temp1->count!=0)){
						int flag1=0;
						for(int j=0;j<temp1->count;j++){
							if((seqTemp-nextSeq)==temp1->seqArr[j]){
								flag1=j;
								break;
							}
						}
						if(flag1!=0){
							temp1->noOfRetran++;							
						}
						//Out of Order Logic
						else{
							if(tempNextSeq != 0){
								if((seqTemp - nextSeq)!=tempNextSeq)
									temp1->oOrderPacket++;
							}
							if(tempNextSeq == 0)
								nextSeq = seqTemp;
							tempNextSeq += byteData;
						}
					}
					if(temp1->count==0){
						temp1->seqArr[0]=1;
						temp1->count +=1;
					}
					else{
						temp1->seqArr[temp1->count] = seqTemp-nextSeq + temp1->seqArr[(temp1->count)-1];
						temp1->count+=1;
					}
				}	
				int winSize = *(packet+48) << 8;
				winSize += *(packet+49);
				temp1->recWinSize +=(winSize*temp1->scaleFactRec);
				if(*(packet+47)==18){
					if(((int)(*(packet+46))/4) == 40)
						temp1->scaleFactRec=1<<(*(packet+73));
					else
						temp1->scaleFactRec=1<<(*(packet+61));
					
				}
				
				break;
			}
		temp1 = temp1->nextPacket;
		}
		tempNextSeq=0;
		
	}
	
	packetList* temp1 = head;
	int cnt=0,sl=1;
	while(temp1!=NULL){
		float tempTime =  temp1->lastTime - temp1->time;
		int x = temp1->lastSec - temp1->sec;
		if(tempTime < 0){
			tempTime = tempTime+1000000;
			if(x>1)
				tempTime = (x-1)*1000000 + tempTime;
		}
		else{
			if(x>=1)
				tempTime = (x)*1000000 + tempTime;
		}
		tempTime = tempTime/1000000;
		cnt++;
		
		temp1->recWinSize /= temp1->noPacketRec;
		temp1->sendWinSize /= temp1->noPacketSender;
		cout<<"<begin: TCP Flow "<<cnt<<">"<<endl;
		opFile<<"<begin: TCP Flow "<<cnt<<">"<<endl;
		//cout<<cnt<<":  Sender IP: "<<temp1->upSendIP<<temp1->lowSendIP<<endl;
		//cout<<"Receiver IP: "<<temp1->upRecIP<<temp1->lowRecIP<<endl;
		//cout<<"Destination Port: "<<temp1->srcPort<<endl;
		opFile<<sl<<". "<<temp1->noPacketSender<<endl;
		cout<<sl++<<". # of packets sent by the sender: "<<temp1->noPacketSender<<endl;
		opFile<<sl<<". "<<temp1->noByteSender<<endl;
		cout<<sl++<<". # of bytes sent by the sender: "<<temp1->noByteSender<<endl;
		opFile<<sl<<". "<<temp1->noPacketRec<<endl;
		cout<<sl++<<". # of packets sent by the receiver: "<<temp1->noPacketRec<<endl;
		opFile<<sl<<". "<<temp1->noByteRec<<endl;
		cout<<sl++<<". # of bytes sent by the receiver: "<<temp1->noByteRec<<endl;
		opFile<<sl<<". "<<temp1->noAckSender<<endl;
		cout<<sl++<<". # of acknowledgement by sender: "<<temp1->noAckSender<<endl;
		opFile<<sl<<". "<<temp1->noAckRec<<endl;
		cout<<sl++<<". # of acknowledgement by receiver: "<<temp1->noAckRec<<endl;
		opFile<<sl<<". "<<temp1->larCongWin<<endl;
		cout<<sl++<<". Largest congestion window size: "<<temp1->larCongWin<<endl;
		opFile<<sl<<". "<<temp1->congTotal/temp1->congCount<<endl;
		cout<<sl++<<". Average congestion window size: "<<temp1->congTotal/temp1->congCount<<endl;
		opFile<<sl<<". "<<temp1->recWinSize<<endl;
		cout<<sl++<<". Average Receiver window size: "<<temp1->recWinSize<<endl;
		opFile<<sl<<". "<<temp1->sendWinSize<<endl;
		cout<<sl++<<". Average Sender window size: "<<temp1->sendWinSize<<endl;
		opFile<<sl<<". "<<temp1->noOfRetran<<endl;
		cout<<sl++<<". # of retransmissions: "<<temp1->noOfRetran<<endl;
		opFile<<sl<<". "<<temp1->oOrderPacket<<endl;
		cout<<sl++<<". # of out-of-order packets: "<<temp1->oOrderPacket<<endl;
		opFile<<sl<<". "<<temp1->throughPut/tempTime<<endl;
		cout<<sl++<<". Throughput of the flow: "<<temp1->throughPut/tempTime<<endl;
		int goodPut=temp1->noByteSender + temp1->noByteRec;
		opFile<<sl<<". "<<goodPut/tempTime<<endl;
		cout<<sl++<<". Goodput of the flow: "<<goodPut/tempTime<<endl;
		opFile<<"<end: TCP Flow "<<cnt<<">"<<endl<<endl;
		cout<<"<end: TCP Flow "<<cnt<<">"<<endl<<endl;
		temp1 = temp1->nextPacket;
		sl=1;
	}
	
	/* 
	xmlFile<<"</report>"<<endl; //Close the xml tag.
	xmlFile.close(); //Close the xml file. */
	printf("\n");
    pcap_close(handle);  //close the pcap file 
	opFile.close();
}
