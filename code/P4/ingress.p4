#include "ingress_match_action.p4"

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

