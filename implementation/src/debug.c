#include "debug.h"

int debug_flow(uint32_t flow_id) {
	uint32_t debug_flow = 10;
	if(DEBUG) {
		if(flow_id  == debug_flow) {
			return 1;
		}
	}
	return 0;
}
