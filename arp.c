/*
 * arp.c
 *
 * By Marc Laroza modified from David C Harrison (david.harrison@ecs.vuw.ac.nz) code September 2016
 *
 * Beyond simplistic ARP implementation.
 *
 */

#include "arp.h"
#include "ip.h"
#include "ethernet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Define some constants */
#define ARP_REQUEST 1       /* ARP protcol opcode for request*/
#define ARP_REPLY 2         /* ARP protcol opcode for reply*/
#define IP_CODE 0x0800
#define IP_ADDRLEN 4

/* Define a struct for ARP header */
typedef struct {
    uint16_t htype;     /* MAC Type */
    uint16_t ptype;     /* Protocol Type */
    uint8_t hlen;       /* MAC Length */
    uint8_t plen;       /* Protocol Length */
    uint16_t opcode;    /* Operation Code : 1 for ARP request and 2 for ARP reply */
    CnetNICaddr src_mac;    /* Sender mac address */
    CnetAddr src_ip;          /* Sender ip address */
    CnetNICaddr dest_mac;   /* Target mac address */
    CnetAddr dest_ip;         /* Target ip address */
}ARP_HEADER;

/*Define the struct for ARP Table and linked list structure*/
typedef struct node
{
    CnetAddr ipAddr;            /* IP Address */
    CnetNICaddr macAddr;   /* MAC Address */
    struct node *next;      
}ARP_TABLE; 

ARP_TABLE *head_node = NULL;        //set the head of the list
ARP_TABLE *current_node = NULL;     //set the currently pointing node

/*Prototypes */
void handle_arp_packet(char *packet);   
void send_arp_response(CnetAddr ip, CnetNICaddr mac, int opcode);   
void print_arp_table();                     
bool exists_arp_table(CnetAddr ip);         
void add_arp_table(CnetAddr ip, CnetNICaddr mac);

/* Handles the arp packet
*  Identify whether the ARP packets received from Ethernet are ARP Requests or ARP Reply
*/
void handle_arp_packet(char *packet){
    ARP_HEADER *arp_packet = (ARP_HEADER *) packet;

    if(arp_packet->opcode == ARP_REQUEST){      //checks if is an ARP request
        if(arp_packet->dest_ip == nodeinfo.address){
            send_arp_response(arp_packet->src_ip, arp_packet->src_mac, ARP_REPLY);
        }
    }
    if(!exists_arp_table(arp_packet->src_ip)) add_arp_table(arp_packet->src_ip, arp_packet->src_mac);
}

bool arp_get_mac_address(CnetAddr cnetAddress, CnetNICaddr macAddress)
{
    print_arp_table();

    if(exists_arp_table(cnetAddress)){
        ARP_TABLE *current = head_node;
        while(current != NULL){
            if(current->ipAddr == cnetAddress){
                macAddress = current->macAddr;
                return true;
            }
            current = current->next;
        }
    }

    CNET_parse_nicaddr(macAddress, "FF:FF:FF:FF:FF:FF");
    send_arp_response(cnetAddress, macAddress, ARP_REQUEST);
    return false; 
}

/* Process the arp response */
void send_arp_response(CnetAddr ip, CnetNICaddr mac, int opcode){
    ARP_HEADER arp_packet;

    arp_packet.htype = 1;
    arp_packet.ptype = IP_CODE;
    arp_packet.hlen = LEN_NICADDR;
    arp_packet.plen = IP_ADDRLEN;
    arp_packet.opcode = opcode;
    memcpy(arp_packet.src_mac, linkinfo[1].nicaddr, sizeof(CnetNICaddr));
    arp_packet.src_ip = nodeinfo.address;
    memcpy(arp_packet.dest_mac, mac, sizeof(CnetNICaddr));
    arp_packet.dest_ip = ip;

    ethernet_send(mac, ETHERTYPE_ARP, (char *)&arp_packet, sizeof(ARP_HEADER));     
}

/*Checks if the ip address exists in the list/table*/
bool exists_arp_table(CnetAddr ip){
    if(head_node == NULL){
        printf("The table is empty\n");
        return false;
    }

    ARP_TABLE *current = head_node;

    while(current != NULL){
        if(current->ipAddr == ip){      //check if the currently pointed node is the IP address
            printf("The IP address exists\n");
            return true;
        }else{
            current = current->next;        //move to the next one
        }
    }
    return false;
}

/*Adds the ip and its corresponding mac address in the arp table*/
void add_arp_table(CnetAddr ip, CnetNICaddr mac){
    ARP_TABLE * new_node = malloc(sizeof(ARP_TABLE));

    new_node->ipAddr = ip;
    memcpy(new_node->macAddr, mac, sizeof(CnetNICaddr));
    new_node->next = NULL;

    if(head_node == NULL){   //check if list is empty, if so, add the new arp packet (node)
        head_node = new_node;
        current_node = head_node;
    }else{          //if its not empty then 
        current_node->next = new_node;
        current_node = new_node;
    }
}

/*Print out the ARP table*/
void print_arp_table(){
    printf("\n ************** ARP TABLE: ************** \n");
    ARP_TABLE *current = head_node;
    char strbuf[24];

    while(current != NULL){
        printf("IP Address: %d, \t", current->ipAddr);
        CNET_format_nicaddr(strbuf, current->macAddr);
        printf("MAC Address: %s\n", strbuf);
        current = current->next;
    }

    printf("\n ************** END ************** \n");
}
