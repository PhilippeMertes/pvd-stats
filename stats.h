#include <pthread.h>

typedef struct pvd_info {
	char *name;
	char **addr;
} t_pvd_info;

typedef struct pvd_max_min_avg {
	double avg;
	double max;
	double min;
	unsigned long nb;
} t_pvd_max_min_avg;

typedef struct pvd_flow {
	u_int8_t src_ip[16];
	u_int8_t dst_ip[16];
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int32_t seq;
	u_int32_t exp_ack;
	struct timeval *ts;
	struct pvd_flow *next;
} t_pvd_flow;

typedef struct pvd_stats {
	t_pvd_info info;
	unsigned long rcvd_cnt;
	unsigned long snt_cnt;
	t_pvd_max_min_avg tput[3]; // [0] = general, [1] = upload, [2] = download
	t_pvd_max_min_avg rtt[3]; // [0] = general, [1] = upload, [2] = download
	t_pvd_flow *flow;
	pthread_mutex_t mutex;
	pthread_mutex_t mutex_acked;
	u_int32_t acked_bytes[3];
} t_pvd_stats;

void free_stats(t_pvd_stats **stats, int size);

int add_flow(t_pvd_stats *stats, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t seq, const u_int32_t exp_ack, const struct timeval ts);

void remove_flow(t_pvd_stats *stats, t_pvd_flow *flow_to_rem);

t_pvd_flow *find_flow(t_pvd_flow *flow, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t ack);

void update_rtt(t_pvd_max_min_avg *rtt, t_pvd_flow *flow, struct timeval ts);