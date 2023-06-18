/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>
//#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

header ethernet_t2 {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ethernet_t3 {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header ipv4_t2 {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header ipv4_t3 {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header udp_t{
    bit<16>     srcport;
    bit<16>     dstport;
    bit<16>     totalLen;
    bit<16>     checksum;
}

header udp_t2{
    bit<16>     srcport;
    bit<16>     dstport;
    bit<16>     totalLen;
    bit<16>     checksum;
}

header ins_t{
    bit<4>   type;
    bit<44>  name;
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   ether_type;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ethernet_t2 eth;
    ethernet_t3 eth_3;
    ipv4_t  ipv4;
    ipv4_t2 ipv4_2;
    ipv4_t3 ipv4_3;
    udp_t udp;
    udp_t2 udp2;
    ins_t  ins;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                out ingress_intrinsic_metadata_t standard_metadata) {

state start{
          /* TODO 1: parse ethernet header */
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
        0x0800: parse_ipv4;
        default: accept;
    }
}

state parse_ipv4{
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
        17: parse_udp;
        default: accept;
    }
}

state parse_udp{
    packet.extract(hdr.udp);
    transition select(hdr.udp.dstport) {
        0x18db: parse_ins;
        default: accept;
    }
}

state parse_ins{
    packet.extract(hdr.ins);
    transition parse_ethernet3;
}

state parse_ethernet3{
    packet.extract(hdr.eth_3);
    transition select(hdr.eth_3.ether_type) {
        0x0800: parse_ipv4_3;
        default: accept;
    }
}

state parse_ipv4_3{
    packet.extract(hdr.ipv4_3);
    transition accept;
}

}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
		  in ingress_intrinsic_metadata_t ig_intr_md,
        	in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        	inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        	inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    
    apply {
        hdr.eth.setValid();
        hdr.ipv4_2.setValid();
        hdr.udp2.setValid();
        hdr.ins.setValid();
        //fuzhi
        hdr.eth.dst_addr = 0xfa163e86762b;
        hdr.eth.src_addr = 0xfa163ecc3b00;
        hdr.eth.ether_type = 0x0800;
        
        //ipv4头赋值
        hdr.ipv4_2.version=0x4;
        hdr.ipv4_2.ihl=0x5;
        hdr.ipv4_2.diffserv=0x00;
        hdr.ipv4_2.total_len=0x0084;
        hdr.ipv4_2.identification=0xe001;
        hdr.ipv4_2.flags=0x0000;
        hdr.ipv4_2.ttl=0x40;
        hdr.ipv4_2.protocol=0x11;
        hdr.ipv4_2.hdr_checksum=0xa87b;
        hdr.ipv4_2.src_addr=0xac100027;
        hdr.ipv4_2.dst_addr=0xac100363;

        //udp头赋值
        hdr.udp2.srcport=0x18db;
        hdr.udp2.dstport=0x18db;
        hdr.udp2.totalLen=0x0070;
        hdr.udp2.checksum=0x9da6;
        
        //ins头赋值
        //hdr.ins.head=0x0536072808076578616d706c65080774657374417070080a72616e646f6d44617461360800000187292ff13712000a0404c5946a0c021770;
        hdr.ins.type = 0x2;
        //name="hello"
        hdr.ins.name = 0x068656c6c6f;

        //macAddr_t tmp = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        //hdr.ethernet.srcAddr = tmp;

       /* TODO 3: set output port    */
       if (hdr.udp.dstport == 0x18db){
        ig_intr_tm_md.ucast_egress_port = 2;
        } else {
       ig_intr_tm_md.ucast_egress_port = 1;
        }

        if (hdr.udp.dstport == 0x18db){
            hdr.eth.setInvalid();
            hdr.ipv4_2.setInvalid();
            hdr.udp2.setInvalid();
            hdr.ins.setInvalid();
            //hdr.ethernet.srcAddr=hdr.eth.src_addr;
            //hdr.ethernet.dstAddr=hdr.eth.dst_addr;
            //hdr.udp.totalLen=  0x000a;
            //hdr.ipv4.total_len = 0x001e;


	        hdr.eth_3.src_addr = 0xfa163ecc3b00;
	        hdr.eth_3.dst_addr = 0xfa163e82e0a2;
            hdr.ipv4_3.src_addr = 0xac100027;
	        hdr.ipv4_3.dst_addr = 0xac100227;


            hdr.ethernet.setInvalid();
            hdr.ipv4.setInvalid();
            hdr.udp.setInvalid();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control EmptyEgress(
        inout headers hdr,
        inout metadata eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, 
inout headers hdr,
        in metadata ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
                packet.emit(hdr.eth);
                packet.emit(hdr.ipv4_2);
                packet.emit(hdr.udp2);
                packet.emit(hdr.ins);
                packet.emit(hdr.ethernet);
                packet.emit(hdr.ipv4);
                packet.emit(hdr.udp);
                
            	packet.emit(hdr.eth_3);
                packet.emit(hdr.ipv4_3);

    /* TODO 4: deparse ethernet header */
    }
}
/////////////////////////////////////////////////////////////////////////////

parser EmptyEgressParser(
        packet_in pkt,
        out headers hdr,
        out metadata eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}
  
control EmptyEgressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(
    MyParser(),
    MyIngress(),
    MyDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;
