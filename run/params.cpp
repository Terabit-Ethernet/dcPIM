#include "params.h"

#include <cmath>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>

DCExpParams params;

/* Read parameters from a config file */
void read_experiment_parameters(std::string conf_filename, uint32_t exp_type) {
    std::ifstream input(conf_filename);
    std::string line;
    std::string key;
    params.interarrival_cdf = "none";
    params.permutation_tm = 0;
    params.worstcase_tm = 0;
    params.incast_tm = 0;
    params.hdr_size = 40;
    params.print_max_min_fairness = false;
    while (std::getline(input, line)) {
        std::istringstream lineStream(line);
        if (line.empty()) {
            continue;
        }


        lineStream >> key;
        assert(key[key.length()-1] == ':');
        key = key.substr(0, key.length()-1);
        if (key == "init_cwnd") {
            lineStream >> params.initial_cwnd;
        }
        else if (key == "max_cwnd") {
            lineStream >> params.max_cwnd;
        }
        else if (key == "retx_timeout") {
            lineStream >> params.retx_timeout_value;
        }
        else if (key == "queue_size") {
            lineStream >> params.queue_size;
        }
        else if (key == "propagation_delay") {
            lineStream >> params.propagation_delay;
        }
        else if (key == "bandwidth") {
            lineStream >> params.bandwidth;
        }
        else if (key == "queue_type") {
            lineStream >> params.queue_type;
        }
        else if (key == "flow_type") {
            lineStream >> params.flow_type;
        }
        else if (key == "num_flow") {
            lineStream >> params.num_flows_to_run;
        }
        else if (key == "flow_trace") {
            lineStream >> params.cdf_or_flow_trace;
        }
        else if (key == "cut_through") {
            lineStream >> params.cut_through;
        }
        else if (key == "mean_flow_size") {
            lineStream >> params.mean_flow_size;
        }
        else if (key == "load_balancing") {
            lineStream >> params.load_balancing;
        }
        else if (key == "preemptive_queue") {
            lineStream >> params.preemptive_queue;
        }
        else if (key == "big_switch") {
            lineStream >> params.big_switch;
        }
        else if (key == "host_type") {
            lineStream >> params.host_type;
        }
        else if (key == "imbalance") {
            lineStream >> params.traffic_imbalance;
        }
        else if (key == "load") {
            lineStream >> params.load;
        }
        else if (key == "traffic_imbalance") {
            lineStream >> params.traffic_imbalance;
        }
        else if (key == "reauth_limit") {
            lineStream >> params.reauth_limit;
        }
        else if (key == "magic_trans_slack") {
            lineStream >> params.magic_trans_slack;
        }
        else if (key == "magic_delay_scheduling") {
            lineStream >> params.magic_delay_scheduling;
        }
        else if (key == "capability_timeout") {
            lineStream >> params.capability_timeout;
        }
        else if (key == "use_flow_trace") {
            lineStream >> params.use_flow_trace;
        }
        else if (key == "smooth_cdf") {
            lineStream >> params.smooth_cdf;
        }
        else if (key == "burst_at_beginning") {
            lineStream >> params.burst_at_beginning;
        }
        else if (key == "capability_resend_timeout") {
            lineStream >> params.capability_resend_timeout;
        }
        else if (key == "capability_initial") {
            lineStream >> params.capability_initial;
        }
        else if (key == "capability_window") {
            lineStream >> params.capability_window;
        }
        else if (key == "capability_prio_thresh") {
            lineStream >> params.capability_prio_thresh;
        }
        else if (key == "capability_third_level") {
            lineStream >> params.capability_third_level;
        }
        else if (key == "capability_fourth_level") {
            lineStream >> params.capability_fourth_level;
        }
        else if (key == "capability_window_timeout") {
            lineStream >> params.capability_window_timeout;
        }
        // For Ranking Algorithm
        else if (key == "token_resend_timeout") {
            lineStream >> params.token_resend_timeout;
        }
        else if (key == "token_timeout") {
            lineStream >> params.token_timeout;
        }
        else if (key == "token_initial") {
            lineStream >> params.token_initial;
        }
        else if (key == "token_window") {
            lineStream >> params.token_window;
        }
        else if (key == "token_window_timeout") {
            lineStream >> params.token_window_timeout;
        }
        else if (key == "token_third_level") {
            lineStream >> params.token_third_level;
        }
        else if (key == "token_fourth_level") {
            lineStream >> params.token_fourth_level;
        }
        else if (key == "rankinghost_idle_timeout") {
            lineStream >> params.rankinghost_idle_timeout;
        }
        else if (key == "ranking_reset_epoch") {
            lineStream >> params.ranking_reset_epoch;
        }
        else if (key == "ranking_max_tokens") {
            lineStream >> params.ranking_max_tokens;
        }
        else if (key == "ranking_controller_epoch") {
            lineStream >> params.ranking_controller_epoch;
        }
        // --------------
        // Multi-Round algorithm
        else if (key == "mr_iter_limit") {
            lineStream >> params.mr_iter_limit;
        }
        else if (key == "mr_epoch") {
            lineStream >> params.mr_epoch;
        }
        else if (key == "mr_window_timeout") {
            lineStream >> params.mr_window_timeout;
        }
        else if (key == "mr_resend_timeout") {
            lineStream >> params.mr_resend_timeout;
        }
        else if (key == "mr_window_size") {
            lineStream >> params.mr_window_size;
        }
        else if (key == "mr_small_flow") {
            lineStream >> params.mr_small_flow;
        }
        else if (key == "mr_low_priority") {
            lineStream >> params.mr_low_priority;
        }
        // -----------------
        else if (key == "ddc") {
            lineStream >> params.ddc;
        }
        else if (key == "ddc_cpu_ratio") {
            lineStream >> params.ddc_cpu_ratio;
        }
        else if (key == "ddc_mem_ratio") {
            lineStream >> params.ddc_mem_ratio;
        }
        else if (key == "ddc_disk_ratio") {
            lineStream >> params.ddc_disk_ratio;
        }
        else if (key == "ddc_normalize") {
            lineStream >> params.ddc_normalize;
        }
        else if (key == "ddc_type") {
            lineStream >> params.ddc_type;
        }
        else if (key == "deadline") {
            lineStream >> params.deadline;
        }
        else if (key == "schedule_by_deadline") {
            lineStream >> params.schedule_by_deadline;
        }
        else if (key == "avg_deadline") {
            lineStream >> params.avg_deadline;
        }
        else if (key == "magic_inflate") {
            lineStream >> params.magic_inflate;
        }
        else if (key == "interarrival_cdf") {
            lineStream >> params.interarrival_cdf;
        }
        else if (key == "num_host_types") {
            lineStream >> params.num_host_types;
        }
        else if (key == "permutation_tm") {
            lineStream >> params.permutation_tm;
        } 
        else if (key == "incast_tm") {
            lineStream >> params.incast_tm;
        }
        else if (key == "outcast_tm") {
            lineStream >> params.outcast_tm;
        }
        else if (key == "worstcase_tm") {
            lineStream >> params.worstcase_tm;
        }
        else if (key == "dctcp_mark_thresh") {
            lineStream >> params.dctcp_mark_thresh;
        }
        else if (key == "hdr_size") {
            lineStream >> params.hdr_size;
            assert(params.hdr_size > 0);
        }
        else if (key == "bytes_mode") {
            lineStream >> params.bytes_mode;
        }
        else if (key == "print_max_min_fairness") {
            lineStream >> params.print_max_min_fairness;
        }
        //else if (key == "dctcp_delayed_ack_freq") {
        //    lineStream >> params.dctcp_delayed_ack_freq;
        //}
        else {
            std::cout << "Unknown conf param: " << key << " in file: " << conf_filename << "\n";
            assert(false);
        }

        params.fastpass_epoch_time = 1500 * 8 * (FASTPASS_EPOCH_PKTS + 0.5) / params.bandwidth;
        // params.ranking_epoch_time = 1500 * 8 * (RANKING_EPOCH_PKTS + 0.5) / params.bandwidth;
        // params.ranking_reset_epoch = 1; 
        params.param_str.append(line);
        params.param_str.append(", ");
    }
    params.rtt = (4 * params.propagation_delay + (1500 * 8 / params.bandwidth) * 2.5) * 2;
    params.ctrl_pkt_rtt = (4 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2.5) * 2;
    params.BDP = ceil(params.rtt * params.bandwidth / 1500 / 8);
    params.ranking_max_tokens = ceil(params.ranking_max_tokens * params.BDP);
    params.token_window *= params.BDP;
    params.token_initial *= params.BDP;
    params.token_timeout *= params.get_full_pkt_tran_delay();
    params.token_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.rankinghost_idle_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.token_window_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.ranking_reset_epoch *= params.BDP * params.get_full_pkt_tran_delay();
    params.ranking_controller_epoch *= params.BDP * params.get_full_pkt_tran_delay();

    // multi-round protocol
    // params.mr_iter_limit = 4;
    // params.mr_epoch = params.iter_limit * params.ctrl_pkt_rtt * 2 + 5;
    // params.mr_window_timeout = 1.0 / 1000000;
    params.mr_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.mr_epoch *= params.BDP * params.get_full_pkt_tran_delay();
    params.mr_window_size *= params.BDP;
    params.mr_small_flow *= params.BDP;
    // std::cout << params.mr_resend_timeout << " " << params.mr_epoch << " " << params.mr_iter_limit << std::endl;
    //std::cout << params.token_initial << " " << params.token_window << " " << params.token_timeout << " " << params.token_window_timeout  << " " << params.token_resend_timeout << " " << params.ranking_max_tokens << " " << params.ranking_reset_epoch << " " << params.ranking_controller_epoch << " " << params.rankinghost_idle_timeout << std::endl;
    // assert(false);
    params.mss = 1460;
}

int DCExpParams::packet_priority(int size_in_pkt, int base) {
    if (base == 0)
        return 1;
    int priority = 1;
    int size = base;
    while(size_in_pkt > size) {
        size *= base;
        priority++;
    }
    if (priority > 6)
        priority = 6;
    return priority;
}
