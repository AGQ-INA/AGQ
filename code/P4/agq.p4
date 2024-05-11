#include <core.p4>
#include <tna.p4>
//#include "registers.p4"
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<32> capacity = 35000; // capacity >= 2^hashid
typedef bit<32> ina_data;
typedef bit<32> hash_id;
typedef bit<29> original_hash_id; // 原本的hash id
typedef bit<3> table_hash_id; // 8个自定义表象
typedef bit<16> job_and_seq_id;

struct control_info{
    bit<16> data0;
    bit<16> data1;
};
//headers
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
    // job_id jobID;
    // seq_id seqID;
    job_and_seq_id jobAndSeq;
    bit<8> workerID; //bit<n>要对应bitmap的位数
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
    // ina_data cdata4;
    // ina_data cdata8;
    // ina_data cdata16;
    bit<8> isACK;
    hash_id hashID;
    original_hash_id hash1;
    table_hash_id hash2;
}
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
    // bit<8> isEmpty_new;
    // hash_id last_hashID;
    // hash_id hashID;
    // bit<8> toDivide;
    // bit<8> last_insert_bitmap;
    bit<8> insert_bitmap;
    // bit<8> insert_bitmap_new;
    bit<8> insert_posi;
    bit<8> insert_len;
    // bit<8> split_posi;
    // bit<8> split_len;
    bit<8> ID_detect;
    // bit<8> startAndCount;
    // ina_data insert_data;
    ina_data mask_clear; // 将对应位置清空
    ina_data mask_extract; // 取出对应部分
    ina_data mask_compress; // 高位截断
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
        meta.ina_action = 2; // change to 2
        meta.worker_agg_now = 0;
        meta.isEmpty = 0;
        // meta.isEmpty_new = 0;
        // meta.toDivide = 0;
        // meta.last_insert_bitmap = 0;
        meta.insert_bitmap = 0;
        // meta.insert_bitmap_new = 0;
        meta.insert_posi = 0;
        meta.insert_len = 0;
        // meta.split_posi = 0;
        // meta.split_len = 0;
        meta.ID_detect = 0;
        // meta.startAndCount = 0;
        // meta.last_hashID = 0;
        // meta.hashID = hdr.ina.hashID;
        // meta.insert_data = 0;
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
        //meta.data = hdr.ina.data0;
        //meta.jobID = hdr.ina.jobID;
        //meta.seqID = hdr.ina.seqID;
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/
control calc_ina_hash(
    in    my_ingress_headers_t   hdr,
    out   hash_id                hash)(
    bit<32>  coeff)
{
    CRCPolynomial<bit<32>>(
        coeff    = coeff,
        reversed = true,
        msb      = false,
        extended = false,
        init     = 0xFFFFFFFF,
        xor      = 0xFFFFFFFF) poly;
    Hash<hash_id>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_hash() {
        hash = hash_algo.get({
                hdr.ina.jobAndSeq
            });
    }

    apply {
        do_hash();
    }
}

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
    Register<bit<8>, original_hash_id>(capacity) pointer;
    RegisterAction<bit<8>, original_hash_id, bit<8>> (pointer)
        pointer_access={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            register_data = 1 - register_data;
        }
    };
    
    Register<bit<8>, original_hash_id>(capacity) data_isEmpty;
    RegisterAction<bit<8>, original_hash_id, bit<8>>(data_isEmpty)
    data_isEmpty_update_and_read={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            register_data = register_data | meta.insert_bitmap;
            
        }
    };
    RegisterAction<bit<8>, original_hash_id, bit<8>>(data_isEmpty)
    data_isEmpty_clear_and_read={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            register_data = register_data - meta.insert_bitmap;
            // result = register_data;
        }
    };
    // Register<bit<8>, original_hash_id>(capacity) data_isEmpty1;
    Register<hash_id, original_hash_id>(capacity) last_hashID0;
    RegisterAction<hash_id, original_hash_id, hash_id>(last_hashID0)
    last_hashID0_update={
        void apply(inout hash_id register_data, out hash_id result){
            result = register_data;
            if(meta.ID_detect == 1 && register_data == 0){
                register_data = hdr.ina.hashID;
            }
            else{
                register_data = 0;
            }
        }
    };
    Register<hash_id, original_hash_id>(capacity) last_hashID1;
    Register<bit<8>, original_hash_id>(capacity) last_division; // 标记上个包是否需要裂变
    RegisterAction<bit<8>, original_hash_id, bit<8>> (last_division)
    last_division_update_and_read={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            register_data = meta.ID_detect;
        }
    };
    // Register<bit<8>, original_hash_id>(capacity) last_division1;
    Register<job_and_seq_id, hash_id>(capacity) job_and_seq_reg;
    RegisterAction<job_and_seq_id, hash_id, bit<8>> (job_and_seq_reg)
    job_and_seq_detect={
        void apply(inout job_and_seq_id register_data, out bit<8> result){
            result = 0;
            if(register_data == 0){ // 为空
                register_data = hdr.ina.jobAndSeq;
                result = 1;
            }
            else if(register_data == hdr.ina.jobAndSeq){ // 可以聚合
                result = 2;
            }
            // result = register_data;
        }
    };
    RegisterAction<job_and_seq_id, hash_id, bit<8>> (job_and_seq_reg)
    job_and_seq_clear={
        void apply(inout job_and_seq_id register_data, out bit<8> result){
            result = 0;
            if(register_data == hdr.ina.jobAndSeq){ // can be cleared
                register_data = 0;
                result = 1;
            }
        }
    };
    Register<bit<8>, original_hash_id>(capacity, 0) start_posi;
    RegisterAction<bit<8>, original_hash_id, bit<8>> (start_posi)
    start_posi_read_and_update={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            if(register_data > 4){
                register_data = register_data - 5;
            }
            else{
                register_data = register_data + 3;
            }
        }
    };
    Register<bit<8>, hash_id>(capacity, 0) insert_posi;
    RegisterAction<bit<8>, hash_id, bit<8>> (insert_posi)
    insert_posi_clear={
        void apply(inout bit<8> register_data, out bit<8> result){
            result = register_data;
            register_data = 0;
        }
    };
    Register<bit<8>, hash_id>(capacity) seq_length;
    RegisterAction<bit<8>, hash_id, bit<8>>(seq_length)
        seq_length_update={
            void apply(inout bit<8> register_data, out bit<8> result){
                
                result = register_data;
            }
    };
    Register<bit<8>, hash_id>(capacity) start_bitmap1;
    // RegisterAction
    Register<bit<8>, hash_id>(capacity, 0) worker_agg; // 聚合的worker数量
    RegisterAction<bit<8>, hash_id, bit<8>>(worker_agg)
        worker_agg_add={
            void apply(inout bit<8> register_data, out bit<8> result){
                register_data = register_data + 1;
                result = register_data;
            }
    };
    Register<ina_data, original_hash_id>(capacity) reg0;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg0)
    reg0_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg0)
    reg0_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data0;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg1;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg1)
    reg1_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg1)
    reg1_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data1;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg2;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg2)
    reg2_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg2)
    reg2_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data2;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg3;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg3)
    reg3_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg3)
    reg3_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data3;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg4;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg4)
    reg4_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg4)
    reg4_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data4;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg5;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg5)
    reg5_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg5)
    reg5_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data5;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg6;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg6)
    reg6_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg6)
    reg6_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data6;
            result = register_data;
        }
    };

    Register<ina_data, original_hash_id>(capacity) reg7;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg7)
    reg7_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg7)
    reg7_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data7;
            result = register_data;
        }
    };

        Register<ina_data, original_hash_id>(capacity) reg8;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg8)
    reg8_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg8)
    reg8_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data8;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg9;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg9)
    reg9_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg9)
    reg9_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data9;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg10;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg10)
    reg10_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg10)
    reg10_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data10;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg11;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg11)
    reg11_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg11)
    reg11_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data11;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg12;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg12)
    reg12_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg12)
    reg12_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data12;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg13;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg13)
    reg13_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg13)
    reg13_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data13;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg14;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg14)
    reg14_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg14)
    reg14_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data14;
            result = register_data;
        }
    };
    Register<ina_data, original_hash_id>(capacity) reg15;
    RegisterAction<ina_data, original_hash_id, ina_data>(reg15)
    reg15_mask={
        void apply(inout ina_data register_data){
            register_data = register_data & meta.mask_clear;
        }
    };
    RegisterAction<ina_data, original_hash_id, ina_data>(reg15)
    reg15_agg={
        void apply(inout ina_data register_data, out ina_data result){
            register_data = register_data + hdr.ina.data15;
            result = register_data;
        }
    };

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    action send_back(){
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }
    table ipv4_host{
        key={hdr.ipv4.dst_addr: exact;}
        actions={send;drop;@defaultonly NoAction;}
        const default_action = NoAction();
        size = 10;
        const entries={
            (0x0a020201): send(176); // 10.2.2.1
            (0x0a020202): send(184); // 10.2.2.2
            (0x0a020203): send(160); // 10.2.2.3
            (0x0a020204): send(168); // 10.2.2.4
        }
    }
    table ina_send_or_drop{
        key={meta.ina_action: exact;}
        actions={send; drop; send_back;}
        default_action = drop();
        size = 16;
        const entries = {
            (0x00):send_back(); (0x02):drop();
            (0x01):send(160); // PS
            (0x03):send(176); // worker
        }
    }
    action split_action(bit<8> c_insert_len, ina_data c_mask, ina_data c_mask_extract, ina_data c_mask_compress){
        meta.insert_len = c_insert_len;
        meta.mask_clear = c_mask; // 对应部分为0，负责清空对应部分的数据
        meta.mask_extract = c_mask_extract; // 对应部分为1，提取出指定位置的数据
        meta.mask_compress = c_mask_compress; // 高位截断
    }
    table split_t0{
        key = {meta.isEmpty: exact; 
                meta.insert_posi: exact;}
        actions = {split_action;}
        size = 2048;
        const entries={
            (0b00000000, 0): split_action(32, 0b00000000000000000000000000000000, 0b11111111111111111111111111111111, 0b11111111111111111111111111111111);
            (0b00000000, 1): split_action(28, 0b11110000000000000000000000000000, 0b00001111111111111111111111111111, 0b11111111111111111111111111110000);
            (0b00000000, 2): split_action(24, 0b11111111000000000000000000000000, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b00000000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b00000000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00000000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00000000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00000000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000001, 0): split_action(28, 0b00000000000000000000000000001111, 0b11111111111111111111111111110000, 0b11111111111111111111111111110000);
            (0b00000001, 1): split_action(24, 0b11110000000000000000000000001111, 0b00001111111111111111111111110000, 0b11111111111111111111111100000000);
            (0b00000001, 2): split_action(20, 0b11111111000000000000000000001111, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b00000001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b00000001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00000001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00000001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00000001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000010, 0): split_action(24, 0b00000000000000000000000011111111, 0b11111111111111111111111100000000, 0b11111111111111111111111100000000);
            (0b00000010, 1): split_action(20, 0b11110000000000000000000011111111, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b00000010, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b00000010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00000010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00000010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00000010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000011, 0): split_action(24, 0b00000000000000000000000011111111, 0b11111111111111111111111100000000, 0b11111111111111111111111100000000);
            (0b00000011, 1): split_action(20, 0b11110000000000000000000011111111, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b00000011, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b00000011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00000011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00000011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00000011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000100, 0): split_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b00000100, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b00000100, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00000100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00000100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00000100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00000100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000101, 0): split_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b00000101, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b00000101, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00000101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00000101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00000101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00000101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000110, 0): split_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b00000110, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b00000110, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00000110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00000110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00000110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000111, 0): split_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b00000111, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b00000111, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00000111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00000111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00000111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00000111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001000, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001000, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001000, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00001000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00001000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001001, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001001, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001001, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00001001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00001001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001010, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001010, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001010, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00001010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001011, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001011, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001011, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00001011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001100, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001100, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001100, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00001100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001101, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001101, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001101, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00001101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001110, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001110, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001110, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001111, 0): split_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001111, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b00001111, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00001111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00001111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00001111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010000, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010000, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00010000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00010000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00010000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010001, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010001, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00010001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00010001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00010001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010010, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010010, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00010010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00010010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010011, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010011, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00010011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00010011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010100, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010100, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00010100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00010100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010101, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010101, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00010101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00010101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010110, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010110, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00010110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010111, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00010111, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00010111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00010111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00010111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00010111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011000, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011000, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00011000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00011000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011001, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011001, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00011001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00011001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011010, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011010, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00011010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011011, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011011, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00011011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011100, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011100, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00011100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011101, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011101, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00011101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011110, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011110, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011111, 0): split_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b00011111, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b00011111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00011111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00011111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100000, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b00100000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00100000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00100000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100001, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b00100001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00100001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00100001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00100001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100010, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00100010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00100010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00100010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100011, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00100011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00100011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00100011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100100, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00100100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00100100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00100100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100101, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00100101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00100101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00100101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100110, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00100110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00100110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100111, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00100111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00100111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00100111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00100111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00100111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101000, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00101000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00101000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101001, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00101001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00101001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101010, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00101010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101011, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00101011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101100, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00101100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101101, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00101101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101110, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101111, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00101111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00101111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00101111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00101111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110000, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00110000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00110000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00110000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110001, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00110001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00110001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00110001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110010, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00110010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00110010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110011, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00110011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00110011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110100, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00110100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00110100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110101, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00110101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00110101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110110, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00110110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110111, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00110111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00110111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00110111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00110111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111000, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00111000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00111000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111001, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00111001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00111001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111010, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00111010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111011, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00111011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111100, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00111100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111101, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00111101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111111, 0): split_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b00111111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b00111111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b00111111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000000, 2): split_action(24, 0b11111111000000000000000000000000, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b01000000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b01000000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01000000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01000000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01000000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000001, 2): split_action(20, 0b11111111000000000000000000001111, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b01000001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b01000001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01000001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01000001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01000001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000010, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b01000010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01000010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01000010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01000010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000011, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b01000011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01000011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01000011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01000011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000100, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01000100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01000100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01000100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01000100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000101, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01000101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01000101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01000101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01000101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000110, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01000110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01000110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01000110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01000111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000111, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01000111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01000111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01000111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01000111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001000, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01001000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01001000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001001, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01001001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01001001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001010, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01001010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001011, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01001011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001100, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01001100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001101, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01001101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001110, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01001111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001111, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01001111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01001111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01001111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01010000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01010000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01010000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01010001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01010001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01010001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01010010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01010010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01010011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01010011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01010100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01010100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01010101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01010101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01010110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01010111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01010111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01010111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01010111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01011000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01011000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01011001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01011001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01011010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01011011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01011100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01011101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01011111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01011111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01011111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b01100000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01100000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01100000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b01100001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01100001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01100001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01100001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01100010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01100010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01100010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01100011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01100011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01100011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01100100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01100100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01100100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01100101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01100101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01100101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01100110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01100110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01100111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01100111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01100111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01101000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01101000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01101001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01101001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01101010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01101011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01101100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01101101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01101111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01101111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01110000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01110000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01110000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01110001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01110001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01110001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01110010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01110010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01110011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01110011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01110100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01110100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01110101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01110101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01110110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01110111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01110111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111000, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01111000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01111000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111001, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01111001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01111001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01111010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111011, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01111011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01111100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111101, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01111101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111111, 0): split_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b01111111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000000, 1): split_action(28, 0b11110000000000000000000000000000, 0b00001111111111111111111111111111, 0b11111111111111111111111111110000);
            (0b10000000, 2): split_action(24, 0b11111111000000000000000000000000, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b10000000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b10000000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10000000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10000000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10000000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000001, 1): split_action(24, 0b11110000000000000000000000001111, 0b00001111111111111111111111110000, 0b11111111111111111111111100000000);
            (0b10000001, 2): split_action(20, 0b11111111000000000000000000001111, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b10000001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b10000001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10000001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10000001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10000001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000010, 1): split_action(20, 0b11110000000000000000000011111111, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b10000010, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b10000010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10000010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10000010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10000010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000011, 1): split_action(20, 0b11110000000000000000000011111111, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b10000011, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b10000011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10000011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10000011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10000011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000100, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b10000100, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10000100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10000100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10000100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10000100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000101, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b10000101, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10000101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10000101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10000101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10000101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000110, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b10000110, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10000110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10000110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10000110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000111, 1): split_action(16, 0b11110000000000000000111111111111, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b10000111, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10000111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10000111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10000111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10000111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001000, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001000, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10001000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10001000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001001, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001001, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10001001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10001001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001010, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001010, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10001010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001011, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001011, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10001011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001100, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001100, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10001100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001101, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001101, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10001101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001110, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001110, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001111, 1): split_action(12, 0b11110000000000001111111111111111, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b10001111, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10001111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10001111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10001111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010000, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10010000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10010000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10010000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010001, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10010001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10010001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10010001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010010, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10010010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10010010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010011, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10010011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10010011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010100, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10010100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10010100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010101, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10010101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10010101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010110, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10010110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010111, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10010111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10010111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10010111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10010111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011000, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10011000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10011000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011001, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10011001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10011001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011010, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10011010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011011, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10011011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011100, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10011100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011101, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10011101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011111, 1): split_action(8, 0b11110000000011111111111111111111, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b10011111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10011111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10011111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b10100000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10100000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10100000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b10100001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10100001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10100001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10100001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10100010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10100010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10100010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10100011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10100011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10100011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10100100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10100100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10100100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10100101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10100101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10100101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10100110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10100110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10100111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10100111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10100111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10100111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10101000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10101000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10101001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10101001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10101010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10101011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10101100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10101101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10101111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10101111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10101111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10110000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10110000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10110000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10110001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10110001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10110001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10110010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10110010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10110011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10110011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10110100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10110100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10110101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10110101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10110110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10110111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10110111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10110111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111000, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10111000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10111000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111001, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10111001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10111001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10111010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111011, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10111011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10111100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111101, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10111101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 1): split_action(4, 0b11110000111111111111111111111111, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b10111111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b10111111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000000, 2): split_action(24, 0b11111111000000000000000000000000, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b11000000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b11000000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11000000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11000000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11000000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000001, 2): split_action(20, 0b11111111000000000000000000001111, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b11000001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b11000001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11000001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11000001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11000001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000010, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b11000010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11000010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11000010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11000010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000011, 2): split_action(16, 0b11111111000000000000000011111111, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b11000011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11000011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11000011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11000011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000100, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11000100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11000100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11000100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11000100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000101, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11000101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11000101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11000101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11000101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000110, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11000110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11000110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11000110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000111, 2): split_action(12, 0b11111111000000000000111111111111, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11000111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11000111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11000111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11000111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001000, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11001000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11001000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001001, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11001001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11001001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001010, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11001010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001011, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11001011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001100, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11001100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001101, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11001101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001111, 2): split_action(8, 0b11111111000000001111111111111111, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11001111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11001111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11001111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11010000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11010000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11010000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11010001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11010001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11010001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11010010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11010010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11010011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11010011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11010100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11010100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11010101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11010101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11010110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11010111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11010111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11010111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011000, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11011000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11011000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011001, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11011001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11011001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11011010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011011, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11011011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11011100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011101, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11011101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 2): split_action(4, 0b11111111000011111111111111111111, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11011111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11011111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100000, 3): split_action(20, 0b11111111111100000000000000000000, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b11100000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11100000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11100000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100001, 3): split_action(16, 0b11111111111100000000000000001111, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b11100001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11100001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11100001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11100001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100010, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11100010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11100010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11100010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100011, 3): split_action(12, 0b11111111111100000000000011111111, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11100011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11100011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11100011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100100, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11100100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11100100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11100100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100101, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11100101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11100101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11100101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11100110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11100110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100111, 3): split_action(8, 0b11111111111100000000111111111111, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11100111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11100111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11100111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101000, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11101000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11101000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101001, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11101001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11101001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11101010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101011, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11101011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11101100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101101, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11101101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 3): split_action(4, 0b11111111111100001111111111111111, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11101111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11101111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110000, 4): split_action(16, 0b11111111111111110000000000000000, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11110000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11110000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11110000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110001, 4): split_action(12, 0b11111111111111110000000000001111, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11110001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11110001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11110001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11110010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11110010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110011, 4): split_action(8, 0b11111111111111110000000011111111, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11110011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11110011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11110100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11110100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110101, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11110101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11110101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11110110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 4): split_action(4, 0b11111111111111110000111111111111, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11110111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11110111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111000, 5): split_action(12, 0b11111111111111111111000000000000, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11111000, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11111000, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111001, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111001, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111001, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111001, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111001, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111001, 5): split_action(8, 0b11111111111111111111000000001111, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11111001, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11111001, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11111010, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111010, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111011, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 5): split_action(4, 0b11111111111111111111000011111111, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11111011, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111011, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111100, 6): split_action(8, 0b11111111111111111111111100000000, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11111100, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111101, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111101, 6): split_action(4, 0b11111111111111111111111100001111, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11111101, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111110, 7): split_action(4, 0b11111111111111111111111111110000, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111111, 0): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 1): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 2): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 3): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 4): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 5): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 6): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
            (0b11111111, 7): split_action(0, 0b11111111111111111111111111111111, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000);
        }
    }
    action ack_action(bit<8> c_insert_len, ina_data c_mask, ina_data c_mask_compress){
        meta.insert_len = c_insert_len;
        meta.mask_clear = c_mask; // 对应部分为0，负责清空对应部分的数据
        // meta.mask_extract = c_mask_extract; // 对应部分为1，提取出指定位置的数据
        meta.mask_compress = c_mask_compress; // 高位截断
    }
    table ack_t{
        key = {meta.isEmpty: exact;
                meta.insert_posi: exact;}
        actions = {ack_action;}
        size = 2048;
        const entries={
            (0b00000001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00000010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00000011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00000011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00000100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00000101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00000101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00000110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00000110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00000111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00000111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00000111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00001000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00001001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b00001001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00001010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00001010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00001011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00001011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00001011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00001100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00001100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00001101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00001101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00001101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00001110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00001110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00001110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00001111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00001111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00001111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00001111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00010000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b00010001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b00010001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00010010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b00010010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00010011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b00010011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00010011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00010100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00010100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00010101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00010101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00010101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00010110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00010110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00010110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00010111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00010111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00010111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00010111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00011000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00011001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b00011001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00011010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00011010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00011011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00011011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00011011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00011100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00011100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00011101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00011101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00011101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00011110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00011110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00011110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00011111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00011111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00011111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00011111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00011111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00100000, 2): ack_action(24, 0b11111111000000000000000000000000, 0b11111111111111111111111100000000);
            (0b00100001, 2): ack_action(20, 0b11111111000000000000000000001111, 0b11111111111111111111000000000000);
            (0b00100001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00100010, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b00100010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00100011, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b00100011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00100011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00100100, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00100101, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00100101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00100110, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00100110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00100111, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00100111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00100111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00101000, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00101001, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b00101001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00101010, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00101010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00101011, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00101011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00101011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00101100, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00101100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00101101, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00101101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00101101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00101110, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00101110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00101110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00101111, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b00101111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00101111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00101111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00101111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00110000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b00110001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b00110001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00110010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b00110010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00110011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b00110011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00110011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00110100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00110100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00110101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00110101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00110101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00110110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00110110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00110110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00110111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00110111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b00110111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00110111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00110111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00111000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b00111001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b00111001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00111010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00111010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00111011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b00111011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00111011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00111100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00111100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00111101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00111101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b00111101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b00111110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00111110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00111110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b00111111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b00111111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b00111111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b00111111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b00111111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b00111111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01000000, 1): ack_action(28, 0b11110000000000000000000000000000, 0b11111111111111111111111111110000);
            (0b01000001, 1): ack_action(24, 0b11110000000000000000000000001111, 0b11111111111111111111111100000000);
            (0b01000001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01000010, 1): ack_action(20, 0b11110000000000000000000011111111, 0b11111111111111111111000000000000);
            (0b01000010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01000011, 1): ack_action(20, 0b11110000000000000000000011111111, 0b11111111111111111111000000000000);
            (0b01000011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01000011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01000100, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b01000100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01000101, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b01000101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01000101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01000110, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b01000110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01000110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01000111, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b01000111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01000111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01000111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01001000, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b01001001, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b01001001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01001010, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01001010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01001011, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01001011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01001011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01001100, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01001100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01001101, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01001101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01001101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01001110, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01001110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01001110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01001111, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b01001111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01001111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01001111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01001111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01010000, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b01010001, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b01010001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01010010, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b01010010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01010011, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b01010011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01010011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01010100, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01010100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01010101, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01010101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01010101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01010110, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01010110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01010110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01010111, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01010111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01010111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01010111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01010111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01011000, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b01011001, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b01011001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01011010, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01011010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01011011, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01011011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01011011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01011100, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01011100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01011101, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01011101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01011101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01011110, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01011110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01011110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01011111, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b01011111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01011111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01011111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01011111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01011111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01100000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100000, 2): ack_action(24, 0b11111111000000000000000000000000, 0b11111111111111111111111100000000);
            (0b01100001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100001, 2): ack_action(20, 0b11111111000000000000000000001111, 0b11111111111111111111000000000000);
            (0b01100001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01100010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100010, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b01100010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01100011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100011, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b01100011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01100011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01100100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100100, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01100101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100101, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01100101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01100110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100110, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01100110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01100111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01100111, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01100111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01100111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01101000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101000, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b01101001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101001, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b01101001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01101010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101010, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01101010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01101011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101011, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01101011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01101011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01101100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101100, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01101100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01101101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101101, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01101101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01101101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01101110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101110, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01101110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01101110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01101111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01101111, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b01101111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01101111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01101111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01101111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01110000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b01110001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b01110001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01110010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b01110010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01110011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b01110011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01110011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01110100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01110100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01110101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01110101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01110101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01110110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01110110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01110110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01110111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01110111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01110111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b01110111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01110111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01110111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01111000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b01111001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b01111001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01111010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01111010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01111011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b01111011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01111011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01111100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01111100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01111101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01111101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b01111101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b01111110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01111110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01111110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b01111111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b01111111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b01111111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b01111111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b01111111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b01111111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b01111111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10000000, 0): ack_action(32, 0b00000000000000000000000000000000, 0b11111111111111111111111111111111);
            (0b10000001, 0): ack_action(28, 0b00000000000000000000000000001111, 0b11111111111111111111111111110000);
            (0b10000001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10000010, 0): ack_action(24, 0b00000000000000000000000011111111, 0b11111111111111111111111100000000);
            (0b10000010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10000011, 0): ack_action(24, 0b00000000000000000000000011111111, 0b11111111111111111111111100000000);
            (0b10000011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10000011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10000100, 0): ack_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000);
            (0b10000100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10000101, 0): ack_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000);
            (0b10000101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10000101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10000110, 0): ack_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000);
            (0b10000110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10000110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10000111, 0): ack_action(20, 0b00000000000000000000111111111111, 0b11111111111111111111000000000000);
            (0b10000111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10000111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10000111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10001000, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001001, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b10001001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10001010, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10001010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10001011, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10001011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10001011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10001100, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10001100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10001101, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10001101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10001101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10001110, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10001110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10001110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10001111, 0): ack_action(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10001111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10001111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10001111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10010000, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b10010001, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b10010001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10010010, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b10010010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10010011, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b10010011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10010011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10010100, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10010100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10010101, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10010101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10010101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10010110, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10010110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10010110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10010111, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10010111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10010111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10010111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10010111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10011000, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10011001, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b10011001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10011010, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10011010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10011011, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10011011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10011011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10011100, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10011100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10011101, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10011101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10011101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10011110, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10011110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10011110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10011111, 0): ack_action(12, 0b00000000000011111111111111111111, 0b11111111111100000000000000000000);
            (0b10011111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10011111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10011111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10011111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10011111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10100000, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100000, 2): ack_action(24, 0b11111111000000000000000000000000, 0b11111111111111111111111100000000);
            (0b10100001, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100001, 2): ack_action(20, 0b11111111000000000000000000001111, 0b11111111111111111111000000000000);
            (0b10100001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10100010, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100010, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b10100010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10100011, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100011, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b10100011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10100011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10100100, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100100, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10100101, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100101, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10100101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10100110, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100110, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10100110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10100111, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10100111, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10100111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10100111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10101000, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101000, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10101001, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101001, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b10101001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10101010, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101010, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10101010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10101011, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101011, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10101011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10101011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10101100, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101100, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10101100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10101101, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101101, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10101101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10101101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10101110, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101110, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10101110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10101110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10101111, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10101111, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b10101111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10101111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10101111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10101111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10110000, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b10110001, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b10110001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10110010, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b10110010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10110011, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b10110011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10110011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10110100, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10110100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10110101, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10110101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10110101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10110110, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10110110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10110110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10110111, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10110111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10110111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b10110111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10110111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10110111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10111000, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10111001, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b10111001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10111010, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10111010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10111011, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b10111011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10111011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10111100, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10111100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10111101, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10111101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b10111101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b10111110, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10111110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10111110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b10111111, 0): ack_action(8, 0b00000000111111111111111111111111, 0b11111111000000000000000000000000);
            (0b10111111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b10111111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b10111111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b10111111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b10111111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b10111111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11000000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000000, 1): ack_action(28, 0b11110000000000000000000000000000, 0b11111111111111111111111111110000);
            (0b11000001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000001, 1): ack_action(24, 0b11110000000000000000000000001111, 0b11111111111111111111111100000000);
            (0b11000001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11000010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000010, 1): ack_action(20, 0b11110000000000000000000011111111, 0b11111111111111111111000000000000);
            (0b11000010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11000011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000011, 1): ack_action(20, 0b11110000000000000000000011111111, 0b11111111111111111111000000000000);
            (0b11000011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11000011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11000100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000100, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b11000100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11000101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000101, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b11000101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11000101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11000110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000110, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b11000110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11000110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11000111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11000111, 1): ack_action(16, 0b11110000000000000000111111111111, 0b11111111111111110000000000000000);
            (0b11000111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11000111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11000111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11001000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001000, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b11001001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001001, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b11001001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11001010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001010, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11001010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11001011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001011, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11001011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11001011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11001100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001100, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11001100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11001101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001101, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11001101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11001101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11001110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001110, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11001110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11001110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11001111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11001111, 1): ack_action(12, 0b11110000000000001111111111111111, 0b11111111111100000000000000000000);
            (0b11001111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11001111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11001111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11001111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11010000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010000, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b11010001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010001, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b11010001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11010010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010010, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b11010010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11010011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010011, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b11010011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11010011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11010100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010100, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11010100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11010101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010101, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11010101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11010101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11010110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010110, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11010110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11010110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11010111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11010111, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11010111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11010111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11010111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11010111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11011000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011000, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b11011001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011001, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b11011001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11011010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011010, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11011010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11011011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011011, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11011011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11011011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11011100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011100, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11011100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11011101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011101, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11011101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11011101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11011110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011110, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11011110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11011110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11011111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11011111, 1): ack_action(8, 0b11110000000011111111111111111111, 0b11111111000000000000000000000000);
            (0b11011111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11011111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11011111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11011111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11011111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11100000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100000, 2): ack_action(24, 0b11111111000000000000000000000000, 0b11111111111111111111111100000000);
            (0b11100001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100001, 2): ack_action(20, 0b11111111000000000000000000001111, 0b11111111111111111111000000000000);
            (0b11100001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11100010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100010, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b11100010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11100011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100011, 2): ack_action(16, 0b11111111000000000000000011111111, 0b11111111111111110000000000000000);
            (0b11100011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11100011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11100100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100100, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11100101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100101, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11100101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11100110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100110, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11100110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11100111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11100111, 2): ack_action(12, 0b11111111000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11100111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11100111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11101000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101000, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b11101001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101001, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b11101001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11101010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101010, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11101010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11101011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101011, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11101011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11101011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11101100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101100, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11101100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11101101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101101, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11101101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11101101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11101110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101110, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11101110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11101110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11101111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11101111, 2): ack_action(8, 0b11111111000000001111111111111111, 0b11111111000000000000000000000000);
            (0b11101111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11101111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11101111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11101111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11110000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110000, 3): ack_action(20, 0b11111111111100000000000000000000, 0b11111111111111111111000000000000);
            (0b11110001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110001, 3): ack_action(16, 0b11111111111100000000000000001111, 0b11111111111111110000000000000000);
            (0b11110001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11110010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110010, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b11110010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11110011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110011, 3): ack_action(12, 0b11111111111100000000000011111111, 0b11111111111100000000000000000000);
            (0b11110011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11110011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11110100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110100, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11110100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11110101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110101, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11110101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11110101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11110110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110110, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11110110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11110110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11110111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11110111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11110111, 3): ack_action(8, 0b11111111111100000000111111111111, 0b11111111000000000000000000000000);
            (0b11110111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11110111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11110111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11111000, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111000, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111000, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111000, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111000, 4): ack_action(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b11111001, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111001, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111001, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111001, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111001, 4): ack_action(12, 0b11111111111111110000000000001111, 0b11111111111100000000000000000000);
            (0b11111001, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11111010, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111010, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111010, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111010, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111010, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11111010, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11111011, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111011, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111011, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111011, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111011, 4): ack_action(8, 0b11111111111111110000000011111111, 0b11111111000000000000000000000000);
            (0b11111011, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11111011, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11111100, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111100, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111100, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111100, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111100, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11111100, 5): ack_action(12, 0b11111111111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11111101, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111101, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111101, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111101, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111101, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11111101, 5): ack_action(8, 0b11111111111111111111000000001111, 0b11111111000000000000000000000000);
            (0b11111101, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
            (0b11111110, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111110, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111110, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111110, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111110, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11111110, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11111110, 6): ack_action(8, 0b11111111111111111111111100000000, 0b11111111000000000000000000000000);
            (0b11111111, 0): ack_action(4, 0b00001111111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111111, 1): ack_action(4, 0b11110000111111111111111111111111, 0b11110000000000000000000000000000);
            (0b11111111, 2): ack_action(4, 0b11111111000011111111111111111111, 0b11110000000000000000000000000000);
            (0b11111111, 3): ack_action(4, 0b11111111111100001111111111111111, 0b11110000000000000000000000000000);
            (0b11111111, 4): ack_action(4, 0b11111111111111110000111111111111, 0b11110000000000000000000000000000);
            (0b11111111, 5): ack_action(4, 0b11111111111111111111000011111111, 0b11110000000000000000000000000000);
            (0b11111111, 6): ack_action(4, 0b11111111111111111111111100001111, 0b11110000000000000000000000000000);
            (0b11111111, 7): ack_action(4, 0b11111111111111111111111111110000, 0b11110000000000000000000000000000);
        }

    }
    action posi_2_bitmap_action(bit<8> c_insert_bitmap){
        meta.insert_bitmap = c_insert_bitmap;
    }
    table posi_2_bitmap_t0{
        key = {meta.insert_posi: exact;}
        actions = {posi_2_bitmap_action;}
        size = 8;
        const entries={
            (0): posi_2_bitmap_action(0b10000000);
            (1): posi_2_bitmap_action(0b01000000);
            (2): posi_2_bitmap_action(0b00100000);
            (3): posi_2_bitmap_action(0b00010000);
            (4): posi_2_bitmap_action(0b00001000);
            (5): posi_2_bitmap_action(0b00000100);
            (6): posi_2_bitmap_action(0b00000010);
            (7): posi_2_bitmap_action(0b00000001);
        }
    }
    table posi_2_bitmap_t1{
        key = {meta.insert_posi: exact;}
        actions = {posi_2_bitmap_action;}
        size = 8;
        const entries={
            (0): posi_2_bitmap_action(0b10000000);
            (1): posi_2_bitmap_action(0b01000000);
            (2): posi_2_bitmap_action(0b00100000);
            (3): posi_2_bitmap_action(0b00010000);
            (4): posi_2_bitmap_action(0b00001000);
            (5): posi_2_bitmap_action(0b00000100);
            (6): posi_2_bitmap_action(0b00000010);
            (7): posi_2_bitmap_action(0b00000001);
        }
    }
    action get_len(bit<8> c_len, ina_data c_mask_extract, ina_data c_mask_compress){
        meta.insert_len = c_len;
        meta.mask_extract = c_mask_extract;
        meta.mask_compress = c_mask_compress; 
    }
    table get_length_t{
        key = {meta.isEmpty: exact;
            meta.insert_posi: exact;
                }
        actions = {get_len;}
        size = 2048;
        const entries={
            (0b00000001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00000011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00000011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00000101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00000101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00000110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00000110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00000111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00000111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00000111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00001001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00001001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00001010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00001011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00001011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00001011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00001100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00001101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00001101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00001101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00001110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00001110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00001110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00001111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00001111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00001111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00001111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b00010001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b00010001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00010010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00010011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00010011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00010011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00010100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00010101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00010101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00010101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00010110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00010110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00010110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00010111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00010111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00010111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00010111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00011001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00011001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00011010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00011011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00011011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00011011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00011100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00011101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00011101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00011101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00011110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00011110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00011110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00011111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00011111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00011111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00011111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00011111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100000, 2): get_len(24, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b00100001, 2): get_len(20, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b00100001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100010, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b00100010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00100011, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b00100011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00100011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100100, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00100100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00100101, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00100101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00100101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00100110, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00100110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00100110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00100111, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b00100111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00100111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00100111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101000, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00101001, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00101001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101010, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00101010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00101011, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00101011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00101011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101100, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00101100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00101101, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00101101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00101101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00101110, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00101110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00101110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00101111, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b00101111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00101111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00101111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00101111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b00110001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b00110001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00110010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00110011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b00110011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00110011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00110100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00110101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00110101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00110101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00110110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00110110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00110110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00110111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00110111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b00110111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00110111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00110111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b00111001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b00111001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00111010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00111011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b00111011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00111011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00111100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b00111101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00111101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b00111101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b00111110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00111110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00111110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b00111111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b00111111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b00111111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b00111111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b00111111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b00111111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000000, 1): get_len(28, 0b00001111111111111111111111111111, 0b11111111111111111111111111110000);
            (0b01000001, 1): get_len(24, 0b00001111111111111111111111110000, 0b11111111111111111111111100000000);
            (0b01000001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000010, 1): get_len(20, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b01000010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01000011, 1): get_len(20, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b01000011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01000011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000100, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b01000100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01000101, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b01000101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01000101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01000110, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b01000110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01000110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01000111, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b01000111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01000111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01000111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001000, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01001001, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01001001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001010, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01001010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01001011, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01001011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01001011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001100, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01001100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01001101, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01001101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01001101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01001110, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01001110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01001110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01001111, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b01001111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01001111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01001111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01001111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010000, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b01010001, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b01010001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010010, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01010010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01010011, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01010011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01010011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010100, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01010100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01010101, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01010101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01010101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01010110, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01010110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01010110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01010111, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01010111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01010111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01010111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01010111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011000, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01011001, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01011001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011010, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01011010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01011011, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01011011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01011011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011100, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01011100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01011101, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01011101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01011101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01011110, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01011110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01011110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01011111, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b01011111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01011111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01011111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01011111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01011111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100000, 2): get_len(24, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b01100001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100001, 2): get_len(20, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b01100001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100010, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b01100010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01100011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100011, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b01100011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01100011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100100, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01100100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01100101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100101, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01100101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01100101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01100110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100110, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01100110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01100110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01100111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01100111, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b01100111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01100111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01100111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101000, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01101001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101001, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01101001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101010, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01101010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01101011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101011, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01101011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01101011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101100, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01101100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01101101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101101, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01101101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01101101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01101110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101110, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01101110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01101110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01101111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01101111, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b01101111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01101111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01101111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01101111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b01110001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b01110001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01110010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01110011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b01110011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01110011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01110100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01110101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01110101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01110101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01110110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01110110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01110110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01110111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01110111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01110111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b01110111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01110111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01110111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b01111001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b01111001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01111010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01111011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b01111011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01111011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01111100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b01111101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01111101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b01111101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b01111110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01111110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01111110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b01111111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b01111111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b01111111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b01111111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b01111111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b01111111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b01111111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000000, 0): get_len(32, 0b11111111111111111111111111111111, 0b11111111111111111111111111111111);
            (0b10000001, 0): get_len(28, 0b11111111111111111111111111110000, 0b11111111111111111111111111110000);
            (0b10000001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000010, 0): get_len(24, 0b11111111111111111111111100000000, 0b11111111111111111111111100000000);
            (0b10000010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10000011, 0): get_len(24, 0b11111111111111111111111100000000, 0b11111111111111111111111100000000);
            (0b10000011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10000011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000100, 0): get_len(20, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b10000100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10000101, 0): get_len(20, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b10000101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10000101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10000110, 0): get_len(20, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b10000110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10000110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10000111, 0): get_len(20, 0b11111111111111111111000000000000, 0b11111111111111111111000000000000);
            (0b10000111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10000111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10000111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001000, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10001001, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10001001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001010, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10001010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10001011, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10001011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10001011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001100, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10001100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10001101, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10001101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10001101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10001110, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10001110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10001110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10001111, 0): get_len(16, 0b11111111111111110000000000000000, 0b11111111111111110000000000000000);
            (0b10001111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10001111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10001111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10001111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010000, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b10010001, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b10010001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010010, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10010010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10010011, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10010011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10010011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010100, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10010100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10010101, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10010101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10010101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10010110, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10010110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10010110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10010111, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10010111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10010111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10010111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10010111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011000, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10011001, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10011001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011010, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10011010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10011011, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10011011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10011011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011100, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10011100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10011101, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10011101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10011101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10011110, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10011110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10011110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10011111, 0): get_len(12, 0b11111111111100000000000000000000, 0b11111111111100000000000000000000);
            (0b10011111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10011111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10011111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10011111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10011111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100000, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100000, 2): get_len(24, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b10100001, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100001, 2): get_len(20, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b10100001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100010, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100010, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b10100010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10100011, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100011, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b10100011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10100011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100100, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100100, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10100100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10100101, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100101, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10100101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10100101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10100110, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100110, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10100110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10100110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10100111, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10100111, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b10100111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10100111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10100111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101000, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101000, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10101001, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101001, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10101001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101010, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101010, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10101010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10101011, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101011, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10101011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10101011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101100, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101100, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10101100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10101101, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101101, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10101101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10101101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10101110, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101110, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10101110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10101110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10101111, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10101111, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b10101111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10101111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10101111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10101111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110000, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b10110001, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b10110001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110010, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10110010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10110011, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b10110011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10110011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110100, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10110100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10110101, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10110101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10110101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10110110, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10110110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10110110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10110111, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10110111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10110111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b10110111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10110111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10110111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111000, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b10111001, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b10111001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111010, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10111010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10111011, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b10111011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10111011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111100, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10111100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b10111101, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10111101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b10111101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b10111110, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10111110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10111110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b10111111, 0): get_len(8, 0b11111111000000000000000000000000, 0b11111111000000000000000000000000);
            (0b10111111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b10111111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b10111111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b10111111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b10111111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b10111111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000000, 1): get_len(28, 0b00001111111111111111111111111111, 0b11111111111111111111111111110000);
            (0b11000001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000001, 1): get_len(24, 0b00001111111111111111111111110000, 0b11111111111111111111111100000000);
            (0b11000001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000010, 1): get_len(20, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b11000010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11000011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000011, 1): get_len(20, 0b00001111111111111111111100000000, 0b11111111111111111111000000000000);
            (0b11000011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11000011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000100, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b11000100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11000101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000101, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b11000101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11000101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11000110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000110, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b11000110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11000110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11000111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11000111, 1): get_len(16, 0b00001111111111111111000000000000, 0b11111111111111110000000000000000);
            (0b11000111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11000111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11000111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001000, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11001001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001001, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11001001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001010, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11001010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11001011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001011, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11001011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11001011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001100, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11001100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11001101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001101, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11001101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11001101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11001110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001110, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11001110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11001110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11001111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11001111, 1): get_len(12, 0b00001111111111110000000000000000, 0b11111111111100000000000000000000);
            (0b11001111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11001111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11001111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11001111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010000, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b11010001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010001, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b11010001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010010, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11010010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11010011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010011, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11010011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11010011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010100, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11010100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11010101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010101, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11010101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11010101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11010110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010110, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11010110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11010110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11010111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11010111, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11010111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11010111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11010111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11010111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011000, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11011001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011001, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11011001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011010, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11011010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11011011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011011, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11011011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11011011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011100, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11011100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11011101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011101, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11011101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11011101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11011110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011110, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11011110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11011110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11011111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11011111, 1): get_len(8, 0b00001111111100000000000000000000, 0b11111111000000000000000000000000);
            (0b11011111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11011111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11011111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11011111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11011111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100000, 2): get_len(24, 0b00000000111111111111111111111111, 0b11111111111111111111111100000000);
            (0b11100001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100001, 2): get_len(20, 0b00000000111111111111111111110000, 0b11111111111111111111000000000000);
            (0b11100001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100010, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b11100010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11100011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100011, 2): get_len(16, 0b00000000111111111111111100000000, 0b11111111111111110000000000000000);
            (0b11100011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11100011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100100, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11100100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11100101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100101, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11100101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11100101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11100110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100110, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11100110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11100110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11100111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11100111, 2): get_len(12, 0b00000000111111111111000000000000, 0b11111111111100000000000000000000);
            (0b11100111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11100111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11100111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101000, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11101001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101001, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11101001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101010, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11101010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11101011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101011, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11101011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11101011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101100, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11101100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11101101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101101, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11101101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11101101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11101110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101110, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11101110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11101110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11101111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11101111, 2): get_len(8, 0b00000000111111110000000000000000, 0b11111111000000000000000000000000);
            (0b11101111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11101111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11101111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11101111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110000, 3): get_len(20, 0b00000000000011111111111111111111, 0b11111111111111111111000000000000);
            (0b11110001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110001, 3): get_len(16, 0b00000000000011111111111111110000, 0b11111111111111110000000000000000);
            (0b11110001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110010, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11110010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11110011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110011, 3): get_len(12, 0b00000000000011111111111100000000, 0b11111111111100000000000000000000);
            (0b11110011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11110011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110100, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11110100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11110101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110101, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11110101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11110101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11110110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110110, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11110110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11110110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11110111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11110111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11110111, 3): get_len(8, 0b00000000000011111111000000000000, 0b11111111000000000000000000000000);
            (0b11110111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11110111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11110111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111000, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111000, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111000, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111000, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111000, 4): get_len(16, 0b00000000000000001111111111111111, 0b11111111111111110000000000000000);
            (0b11111001, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111001, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111001, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111001, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111001, 4): get_len(12, 0b00000000000000001111111111110000, 0b11111111111100000000000000000000);
            (0b11111001, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111010, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111010, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111010, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111010, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111010, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11111010, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11111011, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111011, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111011, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111011, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111011, 4): get_len(8, 0b00000000000000001111111100000000, 0b11111111000000000000000000000000);
            (0b11111011, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11111011, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111100, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111100, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111100, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111100, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111100, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11111100, 5): get_len(12, 0b00000000000000000000111111111111, 0b11111111111100000000000000000000);
            (0b11111101, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111101, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111101, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111101, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111101, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11111101, 5): get_len(8, 0b00000000000000000000111111110000, 0b11111111000000000000000000000000);
            (0b11111101, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
            (0b11111110, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111110, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111110, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111110, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111110, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11111110, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11111110, 6): get_len(8, 0b00000000000000000000000011111111, 0b11111111000000000000000000000000);
            (0b11111111, 0): get_len(4, 0b11110000000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111111, 1): get_len(4, 0b00001111000000000000000000000000, 0b11110000000000000000000000000000);
            (0b11111111, 2): get_len(4, 0b00000000111100000000000000000000, 0b11110000000000000000000000000000);
            (0b11111111, 3): get_len(4, 0b00000000000011110000000000000000, 0b11110000000000000000000000000000);
            (0b11111111, 4): get_len(4, 0b00000000000000001111000000000000, 0b11110000000000000000000000000000);
            (0b11111111, 5): get_len(4, 0b00000000000000000000111100000000, 0b11110000000000000000000000000000);
            (0b11111111, 6): get_len(4, 0b00000000000000000000000011110000, 0b11110000000000000000000000000000);
            (0b11111111, 7): get_len(4, 0b00000000000000000000000000001111, 0b11110000000000000000000000000000);
        }

    }
    action a_case1(){ // posi 4
        hdr.ina.data0 = hdr.ina.data0 >> 4;
        hdr.ina.data1 = hdr.ina.data1 >> 4;
        hdr.ina.data2 = hdr.ina.data2 >> 4;
        hdr.ina.data3 = hdr.ina.data3 >> 4;
        // hdr.ina.data4 = hdr.ina.data4 >> 4;
        // hdr.ina.data5 = hdr.ina.data5 >> 4;
        // hdr.ina.data6 = hdr.ina.data6 >> 4;
        // hdr.ina.data7 = hdr.ina.data7 >> 4;
        // hdr.ina.data8 = hdr.ina.data8 >> 4;
        // hdr.ina.data9 = hdr.ina.data9 >> 4;
        // hdr.ina.data10 = hdr.ina.data10 >> 4;
        // hdr.ina.data11 = hdr.ina.data11 >> 4;
        // hdr.ina.data12 = hdr.ina.data12 >> 4;
        // hdr.ina.data13 = hdr.ina.data13 >> 4;
        // hdr.ina.data14 = hdr.ina.data14 >> 4;
        // hdr.ina.data15 = hdr.ina.data15 >> 4;
    }
    action a_case2(){ // posi 8
        hdr.ina.data0 = hdr.ina.data0 >> 8;
        hdr.ina.data1 = hdr.ina.data1 >> 8;
        hdr.ina.data2 = hdr.ina.data2 >> 8;
        hdr.ina.data3 = hdr.ina.data3 >> 8;
        // hdr.ina.data4 = hdr.ina.data4 >> 8;
        // hdr.ina.data5 = hdr.ina.data5 >> 8;
        // hdr.ina.data6 = hdr.ina.data6 >> 8;
        // hdr.ina.data7 = hdr.ina.data7 >> 8;
        // hdr.ina.data8 = hdr.ina.data8 >> 8;
        // hdr.ina.data9 = hdr.ina.data9 >> 8;
        // hdr.ina.data10 = hdr.ina.data10 >> 8;
        // hdr.ina.data11 = hdr.ina.data11 >> 8;
        // hdr.ina.data12 = hdr.ina.data12 >> 8;
        // hdr.ina.data13 = hdr.ina.data13 >> 8;
        // hdr.ina.data14 = hdr.ina.data14 >> 8;
        // hdr.ina.data15 = hdr.ina.data15 >> 8;
    }
    action a_case3(){ // posi 12
        hdr.ina.data0 = hdr.ina.data0 >> 12;
        hdr.ina.data1 = hdr.ina.data1 >> 12;
        hdr.ina.data2 = hdr.ina.data2 >> 12;
        hdr.ina.data3 = hdr.ina.data3 >> 12;
        // hdr.ina.data4 = hdr.ina.data4 >> 12;
        // hdr.ina.data5 = hdr.ina.data5 >> 12;
        // hdr.ina.data6 = hdr.ina.data6 >> 12;
        // hdr.ina.data7 = hdr.ina.data7 >> 12;
        // hdr.ina.data8 = hdr.ina.data8 >> 12;
        // hdr.ina.data9 = hdr.ina.data9 >> 12;
        // hdr.ina.data10 = hdr.ina.data10 >> 12;
        // hdr.ina.data11 = hdr.ina.data11 >> 12;
        // hdr.ina.data12 = hdr.ina.data12 >> 12;
        // hdr.ina.data13 = hdr.ina.data13 >> 12;
        // hdr.ina.data14 = hdr.ina.data14 >> 12;
        // hdr.ina.data15 = hdr.ina.data15 >> 12;
    }
    action a_case4(){ // posi 16
        hdr.ina.data0 = hdr.ina.data0 >> 16;
        hdr.ina.data1 = hdr.ina.data1 >> 16;
        hdr.ina.data2 = hdr.ina.data2 >> 16;
        hdr.ina.data3 = hdr.ina.data3 >> 16;
        // hdr.ina.data4 = hdr.ina.data4 >> 16;
        // hdr.ina.data5 = hdr.ina.data5 >> 16;
        // hdr.ina.data6 = hdr.ina.data6 >> 16;
        // hdr.ina.data7 = hdr.ina.data7 >> 16;
        // hdr.ina.data8 = hdr.ina.data8 >> 16;
        // hdr.ina.data9 = hdr.ina.data9 >> 16;
        // hdr.ina.data10 = hdr.ina.data10 >> 16;
        // hdr.ina.data11 = hdr.ina.data11 >> 16;
        // hdr.ina.data12 = hdr.ina.data12 >> 16;
        // hdr.ina.data13 = hdr.ina.data13 >> 16;
        // hdr.ina.data14 = hdr.ina.data14 >> 16;
        // hdr.ina.data15 = hdr.ina.data15 >> 16;
    }
    action a_case5(){ // posi 20
        hdr.ina.data0 = hdr.ina.data0 >> 20;
        hdr.ina.data1 = hdr.ina.data1 >> 20;
        hdr.ina.data2 = hdr.ina.data2 >> 20;
        hdr.ina.data3 = hdr.ina.data3 >> 20;
        // hdr.ina.data4 = hdr.ina.data4 >> 20;
        // hdr.ina.data5 = hdr.ina.data5 >> 20;
        // hdr.ina.data6 = hdr.ina.data6 >> 20;
        // hdr.ina.data7 = hdr.ina.data7 >> 20;
        // hdr.ina.data8 = hdr.ina.data8 >> 20;
        // hdr.ina.data9 = hdr.ina.data9 >> 20;
        // hdr.ina.data10 = hdr.ina.data10 >> 20;
        // hdr.ina.data11 = hdr.ina.data11 >> 20;
        // hdr.ina.data12 = hdr.ina.data12 >> 20;
        // hdr.ina.data13 = hdr.ina.data13 >> 20;
        // hdr.ina.data14 = hdr.ina.data14 >> 20;
        // hdr.ina.data15 = hdr.ina.data15 >> 20;
    }
    action a_case6(){ // posi 24
        hdr.ina.data0 = hdr.ina.data0 >> 24;
        hdr.ina.data1 = hdr.ina.data1 >> 24;
        hdr.ina.data2 = hdr.ina.data2 >> 24;
        hdr.ina.data3 = hdr.ina.data3 >> 24;
        // hdr.ina.data4 = hdr.ina.data4 >> 24;
        // hdr.ina.data5 = hdr.ina.data5 >> 24;
        // hdr.ina.data6 = hdr.ina.data6 >> 24;
        // hdr.ina.data7 = hdr.ina.data7 >> 24;
        // hdr.ina.data8 = hdr.ina.data8 >> 24;
        // hdr.ina.data9 = hdr.ina.data9 >> 24;
        // hdr.ina.data10 = hdr.ina.data10 >> 24;
        // hdr.ina.data11 = hdr.ina.data11 >> 24;
        // hdr.ina.data12 = hdr.ina.data12 >> 24;
        // hdr.ina.data13 = hdr.ina.data13 >> 24;
        // hdr.ina.data14 = hdr.ina.data14 >> 24;
        // hdr.ina.data15 = hdr.ina.data15 >> 24;
    }
    action a_case7(){ // posi 28
        hdr.ina.data0 = hdr.ina.data0 >> 28;
        hdr.ina.data1 = hdr.ina.data1 >> 28;
        hdr.ina.data2 = hdr.ina.data2 >> 28;
        hdr.ina.data3 = hdr.ina.data3 >> 28;
        // hdr.ina.data4 = hdr.ina.data4 >> 28;
        // hdr.ina.data5 = hdr.ina.data5 >> 28;
        // hdr.ina.data6 = hdr.ina.data6 >> 28;
        // hdr.ina.data7 = hdr.ina.data7 >> 28;
        // hdr.ina.data8 = hdr.ina.data8 >> 28;
        // hdr.ina.data9 = hdr.ina.data9 >> 28;
        // hdr.ina.data10 = hdr.ina.data10 >> 28;
        // hdr.ina.data11 = hdr.ina.data11 >> 28;
        // hdr.ina.data12 = hdr.ina.data12 >> 28;
        // hdr.ina.data13 = hdr.ina.data13 >> 28;
        // hdr.ina.data14 = hdr.ina.data14 >> 28;
        // hdr.ina.data15 = hdr.ina.data15 >> 28;
    }
    table align_t{
        key = {meta.insert_posi: exact;
                // meta.insert_len: exact;
                }
        actions = {a_case1; a_case2; a_case3; a_case4; a_case5;
                a_case6; a_case7;}
        size = 16;
        const entries={
            (0x01): a_case1(); (0x02): a_case2();
            (0x03): a_case3(); (0x04): a_case4(); (0x05): a_case5();
            (0x06): a_case6(); (0x07): a_case7();
        }
    }
    action e_case1(){
        hdr.ina.data0 = hdr.ina.data0 << 4;
        hdr.ina.data1 = hdr.ina.data1 << 4;
        hdr.ina.data2 = hdr.ina.data2 << 4;
        hdr.ina.data3 = hdr.ina.data3 << 4;
        // hdr.ina.data4 = hdr.ina.data4 << 4;
        // hdr.ina.data5 = hdr.ina.data5 << 4;
        // hdr.ina.data6 = hdr.ina.data6 << 4;
        // hdr.ina.data7 = hdr.ina.data7 << 4;
        // hdr.ina.data8 = hdr.ina.data8 << 4;
        // hdr.ina.data9 = hdr.ina.data9 << 4;
        // hdr.ina.data10 = hdr.ina.data10 << 4;
        // hdr.ina.data11 = hdr.ina.data11 << 4;
        // hdr.ina.data12 = hdr.ina.data12 << 4;
        // hdr.ina.data13 = hdr.ina.data13 << 4;
        // hdr.ina.data14 = hdr.ina.data14 << 4;
        // hdr.ina.data15 = hdr.ina.data15 << 4;
    }
    action e_case2(){
        hdr.ina.data0 = hdr.ina.data0 << 8;
        hdr.ina.data1 = hdr.ina.data1 << 8;
        hdr.ina.data2 = hdr.ina.data2 << 8;
        hdr.ina.data3 = hdr.ina.data3 << 8;
        // hdr.ina.data4 = hdr.ina.data4 << 8;
        // hdr.ina.data5 = hdr.ina.data5 << 8;
        // hdr.ina.data6 = hdr.ina.data6 << 8;
        // hdr.ina.data7 = hdr.ina.data7 << 8;
        // hdr.ina.data8 = hdr.ina.data8 << 8;
        // hdr.ina.data9 = hdr.ina.data9 << 8;
        // hdr.ina.data10 = hdr.ina.data10 << 8;
        // hdr.ina.data11 = hdr.ina.data11 << 8;
        // hdr.ina.data12 = hdr.ina.data12 << 8;
        // hdr.ina.data13 = hdr.ina.data13 << 8;
        // hdr.ina.data14 = hdr.ina.data14 << 8;
        // hdr.ina.data15 = hdr.ina.data15 << 8;
    }
    action e_case3(){
        hdr.ina.data0 = hdr.ina.data0 << 12;
        hdr.ina.data1 = hdr.ina.data1 << 12;
        hdr.ina.data2 = hdr.ina.data2 << 12;
        hdr.ina.data3 = hdr.ina.data3 << 12;
        // hdr.ina.data4 = hdr.ina.data4 << 12;
        // hdr.ina.data5 = hdr.ina.data5 << 12;
        // hdr.ina.data6 = hdr.ina.data6 << 12;
        // hdr.ina.data7 = hdr.ina.data7 << 12;
        // hdr.ina.data8 = hdr.ina.data8 << 12;
        // hdr.ina.data9 = hdr.ina.data9 << 12;
        // hdr.ina.data10 = hdr.ina.data10 << 12;
        // hdr.ina.data11 = hdr.ina.data11 << 12;
        // hdr.ina.data12 = hdr.ina.data12 << 12;
        // hdr.ina.data13 = hdr.ina.data13 << 12;
        // hdr.ina.data14 = hdr.ina.data14 << 12;
        // hdr.ina.data15 = hdr.ina.data15 << 12;
    }
    action e_case4(){
        hdr.ina.data0 = hdr.ina.data0 << 16;
        hdr.ina.data1 = hdr.ina.data1 << 16;
        hdr.ina.data2 = hdr.ina.data2 << 16;
        hdr.ina.data3 = hdr.ina.data3 << 16;
        // hdr.ina.data4 = hdr.ina.data4 << 16;
        // hdr.ina.data5 = hdr.ina.data5 << 16;
        // hdr.ina.data6 = hdr.ina.data6 << 16;
        // hdr.ina.data7 = hdr.ina.data7 << 16;
        // hdr.ina.data8 = hdr.ina.data8 << 16;
        // hdr.ina.data9 = hdr.ina.data9 << 16;
        // hdr.ina.data10 = hdr.ina.data10 << 16;
        // hdr.ina.data11 = hdr.ina.data11 << 16;
        // hdr.ina.data12 = hdr.ina.data12 << 16;
        // hdr.ina.data13 = hdr.ina.data13 << 16;
        // hdr.ina.data14 = hdr.ina.data14 << 16;
        // hdr.ina.data15 = hdr.ina.data15 << 16;
    }
    action e_case5(){
        hdr.ina.data0 = hdr.ina.data0 << 20;
        hdr.ina.data1 = hdr.ina.data1 << 20;
        hdr.ina.data2 = hdr.ina.data2 << 20;
        hdr.ina.data3 = hdr.ina.data3 << 20;
        // hdr.ina.data4 = hdr.ina.data4 << 20;
        // hdr.ina.data5 = hdr.ina.data5 << 20;
        // hdr.ina.data6 = hdr.ina.data6 << 20;
        // hdr.ina.data7 = hdr.ina.data7 << 20;
        // hdr.ina.data8 = hdr.ina.data8 << 20;
        // hdr.ina.data9 = hdr.ina.data9 << 20;
        // hdr.ina.data10 = hdr.ina.data10 << 20;
        // hdr.ina.data11 = hdr.ina.data11 << 20;
        // hdr.ina.data12 = hdr.ina.data12 << 20;
        // hdr.ina.data13 = hdr.ina.data13 << 20;
        // hdr.ina.data14 = hdr.ina.data14 << 20;
        // hdr.ina.data15 = hdr.ina.data15 << 20;
    }
    action e_case6(){
        hdr.ina.data0 = hdr.ina.data0 << 24;
        hdr.ina.data1 = hdr.ina.data1 << 24;
        hdr.ina.data2 = hdr.ina.data2 << 24;
        hdr.ina.data3 = hdr.ina.data3 << 24;
        // hdr.ina.data4 = hdr.ina.data4 << 24;
        // hdr.ina.data5 = hdr.ina.data5 << 24;
        // hdr.ina.data6 = hdr.ina.data6 << 24;
        // hdr.ina.data7 = hdr.ina.data7 << 24;
        // hdr.ina.data8 = hdr.ina.data8 << 24;
        // hdr.ina.data9 = hdr.ina.data9 << 24;
        // hdr.ina.data10 = hdr.ina.data10 << 24;
        // hdr.ina.data11 = hdr.ina.data11 << 24;
        // hdr.ina.data12 = hdr.ina.data12 << 24;
        // hdr.ina.data13 = hdr.ina.data13 << 24;
        // hdr.ina.data14 = hdr.ina.data14 << 24;
        // hdr.ina.data15 = hdr.ina.data15 << 24;
    }
    action e_case7(){
        hdr.ina.data0 = hdr.ina.data0 << 28;
        hdr.ina.data1 = hdr.ina.data1 << 28;
        hdr.ina.data2 = hdr.ina.data2 << 28;
        hdr.ina.data3 = hdr.ina.data3 << 28;
        // hdr.ina.data4 = hdr.ina.data4 << 28;
        // hdr.ina.data5 = hdr.ina.data5 << 28;
        // hdr.ina.data6 = hdr.ina.data6 << 28;
        // hdr.ina.data7 = hdr.ina.data7 << 28;
        // hdr.ina.data8 = hdr.ina.data8 << 28;
        // hdr.ina.data9 = hdr.ina.data9 << 28;
        // hdr.ina.data10 = hdr.ina.data10 << 28;
        // hdr.ina.data11 = hdr.ina.data11 << 28;
        // hdr.ina.data12 = hdr.ina.data12 << 28;
        // hdr.ina.data13 = hdr.ina.data13 << 28;
        // hdr.ina.data14 = hdr.ina.data14 << 28;
        // hdr.ina.data15 = hdr.ina.data15 << 28;
    }
    table data_extract_t{
        key = {meta.insert_posi: exact;
                // meta.insert_len: exact;
                }
        actions = {e_case1; e_case2; e_case3; e_case4; e_case5;
                e_case6; e_case7;}
        size = 16;
        const entries={
            // (0x00, 0x04): e_case08();
            (0x01): e_case1(); (0x02): e_case2(); (0x03): e_case3();
            (0x04): e_case4(); (0x05): e_case5(); (0x06): e_case6();
            (0x07): e_case7();
        }
    }
    bit<8> update_result;
    bit<8> pointer_result;
    bit<8> ID_detect; // 0: hash collision; 1：reg is free; 2: reg is the seq
    hash_id hashID;
    apply{
        if(hdr.ina.isValid()){
            if(hdr.ina.isACK == 0){
                meta.ID_detect = job_and_seq_detect.execute(hdr.ina.hashID);
                if(meta.ID_detect == 1){ // no data here
                    meta.insert_posi = start_posi_read_and_update.execute(hdr.ina.hash1); // read start posi,update the reg_data(+3)
                    insert_posi.write(hdr.ina.hashID, meta.insert_posi);
                    posi_2_bitmap_t0.apply(); // convert to bitmap
                    meta.isEmpty = data_isEmpty_update_and_read.execute(hdr.ina.hash1); // update isempty
                    split_t0.apply(); // get the split info
                    ig_dprsr_md.resubmit_type = 0;
                }
                else if(meta.ID_detect == 2){ // can be aggregated
                    meta.insert_posi = insert_posi.read(hdr.ina.hashID);
                    meta.isEmpty = data_isEmpty.read(hdr.ina.hash1);
                    meta.worker_agg_now = worker_agg_add.execute(hdr.ina.hashID);
                    get_length_t.apply(); // get len and masks
                    if(meta.worker_agg_now == hdr.ina.total_workers){
                        meta.ina_action = 1; // aggregation complete, send to ps
                    }
                }
            }
            else{ // ack
                meta.ina_action = 3;
                meta.insert_len = job_and_seq_clear.execute(hdr.ina.hashID);
                // if meta.insert_len not 0, can go into the following if-else to clear to the reg
                if(meta.insert_len == 1){
                    // start count
                    meta.insert_posi = insert_posi_clear.execute(hdr.ina.hashID); // clear the posi
                    posi_2_bitmap_t1.apply(); // shadow table
                    // meta.isEmpty = data_isEmpty.read(hdr.ina.hash1);
                    meta.isEmpty = data_isEmpty_clear_and_read.execute(hdr.ina.hash1); // clear the corresponding posi
                    worker_agg.write(hdr.ina.hashID, 0);
                    ack_t.apply(); // get len and clear_mask, shadow table
                }
            }
            // hdr.ina.workerID = meta.insert_len;
            // hdr.ina.data6 = 1;
            if(meta.insert_len != 0){ // not hash collision
                // now we get the insert posi and len in the reg
                // align_mask_t.apply();
                // Data truncation
                hdr.ina.data0 = hdr.ina.data0 & meta.mask_compress; 
                hdr.ina.data1 = hdr.ina.data1 & meta.mask_compress;
                hdr.ina.data2 = hdr.ina.data2 & meta.mask_compress;
                hdr.ina.data3 = hdr.ina.data3 & meta.mask_compress;
                // hdr.ina.data4 = 2;
                // hdr.ina.data4 = hdr.ina.data4 & meta.mask_compress; 
                // hdr.ina.data5 = hdr.ina.data5 & meta.mask_compress;
                // hdr.ina.data6 = hdr.ina.data6 & meta.mask_compress;
                // hdr.ina.data7 = hdr.ina.data7 & meta.mask_compress;
                // hdr.ina.data8 = hdr.ina.data8 & meta.mask_compress;
                // hdr.ina.data9 = hdr.ina.data9 & meta.mask_compress;
                // hdr.ina.data10 = hdr.ina.data10 & meta.mask_compress;
                // hdr.ina.data11 = hdr.ina.data11 & meta.mask_compress;
                // hdr.ina.data12 = hdr.ina.data12 & meta.mask_compress;
                // hdr.ina.data13 = hdr.ina.data13 & meta.mask_compress;
                // hdr.ina.data14 = hdr.ina.data14 & meta.mask_compress;
                // hdr.ina.data15 = hdr.ina.data15 & meta.mask_compress;
                align_t.apply(); // align to the insert posi
                // reg对应位置清空
                
                if((meta.ID_detect == 1) || (hdr.ina.isACK == 1)){ // new pkt and ack, need to clear the corresponding region in reg
                    reg0_mask.execute(hdr.ina.hash1);
                    reg1_mask.execute(hdr.ina.hash1);
                    reg2_mask.execute(hdr.ina.hash1);
                    reg3_mask.execute(hdr.ina.hash1);
                    // hdr.ina.data5 = 2;

                    // reg4_mask.execute(hdr.ina.hash1);
                    // reg5_mask.execute(hdr.ina.hash1);
                    // reg6_mask.execute(hdr.ina.hash1);
                    // reg7_mask.execute(hdr.ina.hash1);
                    // reg8_mask.execute(hdr.ina.hash1);
                    // reg9_mask.execute(hdr.ina.hash1);
                    // reg10_mask.execute(hdr.ina.hash1);
                    // reg11_mask.execute(hdr.ina.hash1);
                    // reg12_mask.execute(hdr.ina.hash1);
                    // reg13_mask.execute(hdr.ina.hash1);
                    // reg14_mask.execute(hdr.ina.hash1);
                    // reg15_mask.execute(hdr.ina.hash1);

                    // for new pkt, the original pkt fills in the control table and clears the corresonding region in data reg, the resubmit pkt acts as aggr pkt
                    // if(hdr.ina.isACK == 0){ // new pkt needs to resubmit
                    //     // resubmit
                    //     ig_dprsr_md.resubmit_type = 0;
                    // }
                }
                else{ // aggregation
                    hdr.ina.data0 = reg0_agg.execute(hdr.ina.hash1);
                    hdr.ina.data1 = reg1_agg.execute(hdr.ina.hash1);
                    hdr.ina.data2 = reg2_agg.execute(hdr.ina.hash1);
                    hdr.ina.data3 = reg3_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data5 = 1;

                    // hdr.ina.data4 = reg4_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data5 = reg5_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data6 = reg6_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data7 = reg7_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data8 = reg8_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data9 = reg9_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data10 = reg10_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data11 = reg11_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data12 = reg12_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data13 = reg13_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data14 = reg14_agg.execute(hdr.ina.hash1);
                    // hdr.ina.data15 = reg15_agg.execute(hdr.ina.hash1);

                    // extract the corresonding data and shift
                    // data_mask_t.apply();
                    hdr.ina.data0 = hdr.ina.data0 & meta.mask_extract;
                    hdr.ina.data1 = hdr.ina.data1 & meta.mask_extract;
                    hdr.ina.data2 = hdr.ina.data2 & meta.mask_extract;
                    hdr.ina.data3 = hdr.ina.data3 & meta.mask_extract;

                    // hdr.ina.data4 = hdr.ina.data4 & meta.mask_extract;
                    // hdr.ina.data5 = hdr.ina.data5 & meta.mask_extract;
                    // hdr.ina.data6 = hdr.ina.data6 & meta.mask_extract;
                    // hdr.ina.data7 = hdr.ina.data7 & meta.mask_extract;
                    // hdr.ina.data8 = hdr.ina.data8 & meta.mask_extract;
                    // hdr.ina.data9 = hdr.ina.data9 & meta.mask_extract;
                    // hdr.ina.data10 = hdr.ina.data10 & meta.mask_extract;
                    // hdr.ina.data11 = hdr.ina.data11 & meta.mask_extract;
                    // hdr.ina.data12 = hdr.ina.data12 & meta.mask_extract;
                    // hdr.ina.data13 = hdr.ina.data13 & meta.mask_extract;
                    // hdr.ina.data14 = hdr.ina.data14 & meta.mask_extract;
                    // hdr.ina.data15 = hdr.ina.data15 & meta.mask_extract;
                    data_extract_t.apply(); // shift to the highest bit
                }
            }
            // else{
            //     // hdr.ina.data5 = 3;
            //     // hdr.ina.workerID = meta.ID_detect;
            // }
            // if(meta.insert_len != 0){ // 可以聚合
            //     // 至此获取了在reg中的start和len
            //     align_mask_t.apply();
            //     align_t.apply(); // 对齐
            //     if(hdr.ina.isACK == 0){
            //         // reg对应位置清空
            //         if(meta.mask_clear != 0){ // 新包先清空对应位置
            //             reg0_mask.execute(hdr.ina.hash1);
            //             // resubmit
            //             ig_dprsr_md.resubmit_type = 0;
            //         }
            //         else{ // 聚合
            //             meta.worker_agg_now = worker_agg_add.execute(hdr.ina.hashID);
            //             hdr.ina.data0 = reg0_agg.execute(hdr.ina.hash1);
            //             // 提取出对应位置数据，并移位到最高位
            //             data_mask_t.apply();
            //             data_extract_t.apply();
            //         }
            //     }
            //     else{
            //         // 清空数据或许可以和上面新包的结合下
            //     }
            // }

            // hdr.ina.workerID = meta.ID_detect; // del
            ina_send_or_drop.apply();

        }
        else{ // ipv4 forward
            if(hdr.ipv4.isValid()){
                ipv4_host.apply();
            }
        }
    }
    
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Resubmit() resubmit;
    apply {
        if(ig_dprsr_md.resubmit_type == 0){
            resubmit.emit();
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;