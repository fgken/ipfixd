#ifndef __LOG_H__
#define __LOG_H__

enum {
	LOG_ERR,
	LOG_WARN,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
};

#define log(level, msg, ...)	{ \
	fprintf(stderr, msg, ##__VA_ARGS__); \
	fprintf(stderr, "\n"); \
}
#define log_err(msg, ...)		log(LOG_ERR, msg, ##__VA_ARGS__)
#define log_warn(msg, ...)		log(LOG_WARN, msg, ##__VA_ARGS__)
#define log_notice(msg, ...)	log(LOG_NOTICE, msg, ##__VA_ARGS__)
#define log_info(msg, ...)		log(LOG_INFO, msg, ##__VA_ARGS__)
#define log_debug(msg, ...)		log(LOG_DEBUG, msg, ##__VA_ARGS__)
#define fatal_exit(msg, ...)	{ \
	log(LOG_ERR, msg, ##__VA_ARGS__); \
	exit(1); \
}

#endif /* __LOG_H__*/
