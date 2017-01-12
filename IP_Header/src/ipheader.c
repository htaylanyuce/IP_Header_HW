#include <stdio.h>
#include <arpa/inet.h>
#include "ipheader.h"


/* Parses the given buffer into an IP header structure.
 *
 * Parameters:
 * ip: pointer to the IP header structure that will be filled based
 *      on the data in the buffer
 * buffer: buffer of 20 bytes that contain the IP header. */
void parseIp(struct ipHeader *ip, const void *buffer)
{
    int len;
    ip->version = (*((int*)buffer) >> 4) & 0x0F;
    len= (*((int*)buffer)) & 0x0F;
    ip->ihl = len* 4;
    ip->dscp = (*(int*)(buffer+1)>>2) & 0x3f;
    ip->ecn =  *(int*)(buffer+1) & 0x03;

    ip->length = ((*(unsigned short*)(buffer+2)) & 0xff) << 8;
    ip->length |= (*(unsigned short*)(buffer+3)) & 0xff;


    ip->flags = ((*(int*)(buffer+6)) >> 5) & 0x07;
    ip->fragment_offset = (*(int*)(buffer+6) & 0x1F) <<  8 | (*(int*)(buffer+7)) & 0xFF;
    ip->time_to_live = *(int*)(buffer+8) & 0xFF;
    ip->protocol = *(int*)(buffer+9) & 0xFF;
     ip->identification =(*(unsigned short*)(buffer+4)& 0xff) << 8 | (*(unsigned short*)(buffer+5))& 0xFF;
    ip->header_checksum = (*(unsigned char*)(buffer+10))<< 8 | *(unsigned char*)(buffer+11);

    for(int i = 0 ;i < 4; i++)
    {
        ip->source_ip[i] = *(unsigned char*)(buffer+12+i);
        ip->destination_ip[i] = *(unsigned char*)(buffer+16+i);
    }


}


/* Builds a 20-byte byte stream based on the given IP header structure
 *
 * Parameters:
 * buffer: pointer to the 20-byte buffer to which the header is constructed
 * ip: IP header structure that will be packed to the buffer */
void sendIp(void *buffer, const struct ipHeader *ip)
{

    *(char*)buffer = (char)((ip->version << 4)| ip->ihl/4);
    *(int*)(buffer+1) = (int)(ip->dscp << 2) | (ip->ecn & 0x03);
    *(int*)(buffer+2) = (unsigned short)(ip->length >> 8 & 0xFF);
    *(int*)(buffer+3) = (unsigned short)(ip->length & 0xFF);
    *(int*)(buffer+4) = (unsigned short)(ip->identification >> 8) & (0xFF);
    *(int*)(buffer+5) = (unsigned short)(ip->identification) & (0xFF);
    *(int*)(buffer+6) = (ip->flags) << 5 & 0xE0;
    *(int*)(buffer+6) |= ((ip->fragment_offset >> 8) & 0x1F);
    *(int*)(buffer+7) = ip->fragment_offset & 0xFF;
    *(char*)(buffer+8) = (char)ip->time_to_live & 0xFF;
    *(int*)(buffer+9) = ip->protocol & 0xFF;
    *(unsigned short*)(buffer+10) = (unsigned short)(ip->header_checksum >> 8) & 0xFF;
    *(unsigned short*)(buffer+11) |= (unsigned short)(ip->header_checksum) & 0xFF;

    for(int i = 0; i < 4 ; i++)
    {
        *(unsigned char*)(buffer+12+i) = (unsigned char)ip->source_ip[i];
        *(unsigned char*)(buffer+16+i) = (unsigned char)ip->destination_ip[i];
    }

}


/* Prints the given IP header structure */
void printIp(const struct ipHeader *ip)
{
    /* Note: ntohs below is for converting numbers from network byte order
     to host byte order. You can ignore them for now
     To be discussed further in Network Programming course... */
    printf("version: %d   ihl: %d   dscp: %d   ecn: %d\n",
            ip->version, ip->ihl, ip->dscp, ip->ecn);
    printf("length: %d   id: %d   flags: %d   offset: %d\n",
            ntohs(ip->length), ntohs(ip->identification), ip->flags, ip->fragment_offset);
    printf("time to live: %d   protocol: %d   checksum: 0x%04x\n",
            ip->time_to_live, ip->protocol, ntohs(ip->header_checksum));
    printf("source ip: %d.%d.%d.%d\n", ip->source_ip[0], ip->source_ip[1],
            ip->source_ip[2], ip->source_ip[3]);
    printf("destination ip: %d.%d.%d.%d\n", ip->destination_ip[0],
            ip->destination_ip[1],
            ip->destination_ip[2], ip->destination_ip[3]);
}

/* Shows hexdump of given data buffer */
void hexdump(const void *buffer, unsigned int length)
{
    const unsigned char *cbuf = buffer;
    unsigned int i;
    for (i = 0; i < length; ) {
        printf("%02x ", cbuf[i]);
        i++;
        if (!(i % 8))
            printf("\n");
    }
}
