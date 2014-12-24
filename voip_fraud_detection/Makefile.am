bin_PROGRAMS=voip_fraud_detection
voip_fraud_detection_SOURCES=voip_fraud_detection.c \
                             voip_fraud_detection.h \
                             prefix_examination.c \
                             prefix_examination.h \
                             country.c \
                             country.h \
                             cache_node_no_attack.c \
                             cache_node_no_attack.h \
                             output.c \
                             output.h \
                             data_structure.h \
                             data_structure.c \
                             configuration.h
voip_fraud_detection_LDADD=-lunirec -ltrap -lm -lnemea-common

#AM_CFLAGS = -D ENABLE_GEOIP
#AM_CFLAGS += `pkg-config --cflags geoip`
#AM_LDFLAGS = `pkg-config --libs geoip`
