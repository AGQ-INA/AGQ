#include "headers.p4"

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    udp_h        udp;
    INA_h        ina;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<8> worker_agg_now;
    bit<8> ina_action;
    bit<8> isEmpty;
    bit<8> insert_bitmap;
    bit<8> start_posi;
    bit<8> insert_len;
    bit<8> ID_detect;
    ina_data mask_clear; // clear the corresponding bits
    ina_data mask_extract; // extract the corresponding bits
    ina_data mask_compress; // truncation at high bits
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }
    state meta_init{
        meta.ina_action = 2; // default: drop
        meta.worker_agg_now = 0;
        meta.isEmpty = 0;
        meta.insert_bitmap = 0;
        meta.start_posi = 0;
        meta.insert_len = 0;
        meta.ID_detect = 0;
        meta.mask_clear = 0;
        meta.mask_extract = 0;
        meta.mask_compress = 0;
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID:  parse_vlan_tag;
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            17: parse_udp;
            default: accept;
        }
    }

    state parse_udp{
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port){
            50000: parse_INA;
            50001: parse_INA;
            default: accept;
        }
    }
    state parse_INA {
        pkt.extract(hdr.ina);
        transition accept;
    }

}