#include <tna.p4>
#include <core.p4>
//headers
typedef bit<32> ina_data; // uint32
typedef bit<16> hash_id;
typedef bit<13> original_hash_id; // len = len(hash_ID)-3
typedef bit<3> table_hash_id; // can include up to 8 gradients within 1 aggregator
typedef bit<16> job_and_seq_id;

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

header INA_h{
    job_and_seq_id jobAndSeq;
    bit<8> workerID;
    bit<8> total_workers;
    ina_data data0;
    ina_data data1;
    ina_data data2;
    ina_data data3;
    ina_data data4;
    ina_data data5;
    ina_data data6;
    ina_data data7;
    ina_data data8;
    ina_data data9;
    ina_data data10;
    ina_data data11;
    ina_data data12;
    ina_data data13;
    ina_data data14;
    ina_data data15;
    bit<8> isACK;
    hash_id hashID;
    original_hash_id hash1;
    table_hash_id hash2;
}