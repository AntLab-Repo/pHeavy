/* -*- P4_16 -*- */ 
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "common/util.p4"
#include "common/headers.p4"

typedef bit<32> timestamp_type;
typedef bit<16> len_type;
typedef bit<8> flag_type;

const bit<32> FLOW_ENTRIES = 4;
const bit<32> IAT_limit = 32w9155273;

header my_metadata_t {
    flag_type o_ack_counter;
    flag_type o_psh_counter;
    flag_type o_syn_counter;
    len_type o_len_min;
    len_type o_len_max;
    len_type o_len_total;
};

struct metadata_t {
	my_metadata_t my_metadata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
        
    TofinoIngressParser() tofino_parser;
    
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
       pkt.extract(hdr.udp);
       transition accept;
    }

    state parse_tcp {
       pkt.extract(hdr.tcp);
       transition accept;
    }
}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
/*
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}
*/

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {    
    
    /* Fig. 4 in our paper: IAT_flag */   
    bit<1> shadow_time_flag = 0;
    /* Fig. 4 in our paper: TCP_flag */
    bit<1> shadow_tcp_flag = 0;
    /* Fig. 4 in our paper: 1st_flag */
    bit<8> count_empty;
    /* The flag decides whether the init needs */
    /* shadow_init_flag = IAT_flag || 1st_flag || TCP_flag*/
    bit<1> shadow_init_flag = 0;
    /*Hash result*/
    bit<32> flow_hash_res = 0;
    /*IAT result*/
    bit<32> s_IAT_temp = 0;
    /* Identify the i-th packet of the flow */
    bit<32> shadow_counter = 0;
    /*Metadata Time temp*/
    bit<32> feature_ingress_time_temp = (bit<32>) (ig_intr_md.ingress_mac_tstamp>>16);

    /*****************     shadow register    *************************/
    /* Timestamp_reg */
    Register<timestamp_type, bit<32>>(FLOW_ENTRIES, 32w0) shadow_timestamp;
    RegisterAction<timestamp_type, bit<32>, bit<1>>(shadow_timestamp) shadow_timestamp_action = {
        void apply(inout timestamp_type value, out bit<1> output){
            timestamp_type time_temp = (timestamp_type)feature_ingress_time_temp - value;  
            if(time_temp > IAT_limit){
                output = 1;
            }
            value = (timestamp_type) feature_ingress_time_temp;
        }
    };

    /* Counter */
    Register<bit<32>, bit<32>>(FLOW_ENTRIES, 32w0) feature_counter;
    RegisterAction<bit<32>, bit<32>, bit<32>>(feature_counter) feature_counter_action = {
        void apply(inout bit<32> value, out bit<32> output){
            value = value + 1;
            output = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(feature_counter) feature_counter_action_time_flag = {
        void apply(inout bit<32> value, out bit<32> output){
            if(shadow_tcp_flag == 1){
                value = 0;
            }
            value = 1;
            output = value;
        }
    };
    /* First_packet_reg*/
    Register<bit<8>, bit<32>>(FLOW_ENTRIES, 8w0) shadow_counter_req;
    RegisterAction<bit<8>, bit<32>, bit<8>>(shadow_counter_req) shadow_counter_req_action = {
        void apply(inout bit<8> value, out bit<8> output){
            output = value;
            if(shadow_tcp_flag == 1){
                value = 0;
            } 
            else if(value == 0){
                value = 1;
            }
        }
    };
    
    /* SYN Flag feature */
    Register<bit<8>, bit<32>>(FLOW_ENTRIES, 8w0) feature_syn;
    RegisterAction<bit<8>, bit<32>, bit<8>>(feature_syn) feature_syn_action = {
        void apply(inout bit<8> value, out bit<8> output){
            value = (bit<8>)hdr.tcp.syn + value;
            output = value;
        }
    };
    RegisterAction<bit<8>, bit<32>, bit<32>>(feature_syn) feature_syn_action_time_flag = {
        void apply(inout bit<8> value){
             value = (bit<8>)hdr.tcp.syn;
             if(shadow_tcp_flag == 1){
                value = 0;
            }
        }
    };
    /* PSH Flag feature */
    Register<bit<8>, bit<32>>(FLOW_ENTRIES, 8w0) feature_psh;
    RegisterAction<bit<8>, bit<32>, bit<8>>(feature_psh) feature_psh_action = {
        void apply(inout bit<8> value, out bit<8> output){
            value = (bit<8>)hdr.tcp.psh + value;
            output = value;
        }
    };
    RegisterAction<bit<8>, bit<32>, bit<32>>(feature_psh) feature_psh_action_time_flag = {
        void apply(inout bit<8> value){
             value = (bit<8>)hdr.tcp.psh;
             if(shadow_tcp_flag == 1){
                value = 0;
            }
        }
    };
    /* ACK Flag feature */
    Register<bit<8>, bit<32>>(FLOW_ENTRIES, 8w0) feature_ack;
    RegisterAction<bit<8>, bit<32>, bit<8>>(feature_ack) feature_ack_action = {
        void apply(inout bit<8> value, out bit<8> output){
            value = (bit<8>)hdr.tcp.ack + value;
            output = value;
        }
    };
    RegisterAction<bit<8>, bit<32>, bit<32>>(feature_ack) feature_ack_action_time_flag = {
        void apply(inout bit<8> value){
             value = (bit<8>)hdr.tcp.ack;
             if(shadow_tcp_flag == 1){
                value = 0;
            }
        }
    };
    
    /* Time feature */
    /* Tofino does not support range matching with a feature whose length is greater than or equal to 31 bits */

    /* MIN Length feature */
    Register<len_type, bit<32>>(FLOW_ENTRIES, 16w0) feature_len_min;
    RegisterAction<len_type, bit<32>, len_type>(feature_len_min) feature_len_min_action = {
        void apply(inout len_type value, out len_type output){
            if(value > hdr.ipv4.total_len){
                value = hdr.ipv4.total_len;
            } 
            output = value;
        }
    };
    RegisterAction<len_type, bit<32>, len_type>(feature_len_min) feature_len_min_action_time_flag = {
        void apply(inout len_type value){
             value = hdr.ipv4.total_len;
        }
    };
    
    /* MAX Length feature */
    Register<len_type, bit<32>>(FLOW_ENTRIES, 16w0) feature_len_max;
    RegisterAction<len_type, bit<32>, len_type>(feature_len_max) feature_len_max_action = {
        void apply(inout len_type value, out len_type output){
            if(value < hdr.ipv4.total_len){
                value = hdr.ipv4.total_len;
            }
            output = value;
        }
    };
    RegisterAction<len_type, bit<32>, len_type>(feature_len_max) feature_len_max_action_time_flag = {
        void apply(inout len_type value){
             value = hdr.ipv4.total_len;
        }
    };
    /* TOTAL Length feature */
    Register<len_type, bit<32>>(FLOW_ENTRIES, 16w0) feature_len_total;
    RegisterAction<len_type, bit<32>, len_type>(feature_len_total) feature_len_total_action = {
        void apply(inout len_type value, out len_type output){
            value = value + hdr.ipv4.total_len;
            output = value;
        }
    };
    RegisterAction<len_type, bit<32>, len_type>(feature_len_total) feature_len_total_action_time_flag = {
        void apply(inout len_type value){
             value = hdr.ipv4.total_len;
        }
    };
    
    
    Hash<bit<32>>(HashAlgorithm_t.RANDOM) hash_1;
    
    action drop() {
        ig_dprsr_md.drop_ctl = 0;
    }

    action h_flow(){
        /* Actions for heavy flows */
    }
    

    action not_h_flow(){
        /* Actions for non heavy flows */
    }

    table DT {
        key = {
            /* Matching keys*/
            hdr.ipv4.protocol : exact;
            hdr.tcp.dst_port : range;
            ig_md.my_metadata.o_psh_counter : range;
            ig_md.my_metadata.o_len_min : range;
            ig_md.my_metadata.o_len_max : range;
        }
        actions = {
            h_flow;
            not_h_flow;
            drop;
        }
        const default_action = drop;
        size = 1024;
    }

    apply{
            /* Hash */
            flow_hash_res = hash_1.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol}, 32w0, FLOW_ENTRIES);

            /* If TCP terminal flag */
            if(hdr.tcp.fin ==1 || hdr.tcp.res ==1){
                shadow_tcp_flag = 1;
            }

            count_empty = shadow_counter_req_action.execute(flow_hash_res);
            shadow_time_flag = shadow_timestamp_action.execute(flow_hash_res);                        
            if(count_empty == 0){
                shadow_time_flag = 1;
            }
            /* shadow_init_flag = IAT_flag || 1st_flag || TCP_flag */
            if(shadow_tcp_flag == 1 || shadow_time_flag == 1){
                shadow_init_flag = 1;
            }

            /* Initialize memory space */
            if(shadow_init_flag == 1){
            shadow_counter = feature_counter_action_time_flag.execute(flow_hash_res);                
            feature_ack_action_time_flag.execute(flow_hash_res);
            feature_syn_action_time_flag.execute(flow_hash_res);
            feature_psh_action_time_flag.execute(flow_hash_res);           
            ig_md.my_metadata.o_len_min = feature_len_min_action_time_flag.execute(flow_hash_res);
            ig_md.my_metadata.o_len_max = feature_len_max_action_time_flag.execute(flow_hash_res);
            ig_md.my_metadata.o_len_total = feature_len_total_action_time_flag.execute(flow_hash_res);  
            }

            /* Update memory space */
            else{
            shadow_counter = feature_counter_action.execute(flow_hash_res);
            ig_md.my_metadata.o_ack_counter = feature_ack_action.execute(flow_hash_res);
            ig_md.my_metadata.o_syn_counter = feature_syn_action.execute(flow_hash_res);
            ig_md.my_metadata.o_psh_counter = feature_psh_action.execute(flow_hash_res);            
            ig_md.my_metadata.o_len_min = feature_len_min_action.execute(flow_hash_res);
            ig_md.my_metadata.o_len_max = feature_len_max_action.execute(flow_hash_res);
            ig_md.my_metadata.o_len_total = feature_len_total_action.execute(flow_hash_res);  
            }

            forward.apply();
            if(shadow_counter == 5){
                DT.apply();
            }
            
        }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
/*
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}
*/

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
        
    
    apply {
        
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),//
         SwitchIngressDeparser(),//
         SwitchEgressParser(), //
         EmptyEgress<header_t, metadata_t>(),
         EmptyEgressDeparser<header_t, metadata_t>()) pipe;

Switch(pipe) main;

