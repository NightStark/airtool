#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/wireless.h>

#include <netpacket/packet.h>

#include "osdep/le_struct.h"
#include "osdep/byteorder.h"
#include "osdep/common.h"
#include "osdep/crctable_osdep.h"

#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"

#include "lib/iwlib.h"

#include <asm/byteorder.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER     _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER     _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#include "ieee80211/include/ieee80211.h"

/* radiotap-parser defines types like u8 that
		 * ieee80211_radiotap.h needs
		 *
		 * we use our local copy of ieee80211_radiotap.h
		 *
		 * - since we can't support extensions we don't understand
		 * - since linux does not include it in userspace headers
		 */

#define AIR_LOG(fmt, ...) \
    printf("[%s][%d] INFO  - " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define AIR_ERR(fmt, ...) \
    printf("[%s][%d] ERROR - " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X,"
#define MAC_PRINT(m) m[0], m[1], m[2], m[3], m[4], m[5]

///////////////////////////////////////////////////////////////////////////////

#ifndef offsetof
#define offsetof(type, field)   ((size_t)(&((type *)0)->field))
#endif


#ifndef __packed
#define __packed __attribute__((__packed__))
#endif /* __packed */

struct rx_info
{
	uint64_t ri_mactime;
	int32_t ri_power;
	int32_t ri_noise;
	uint32_t ri_channel;
	uint32_t ri_freq;
	uint32_t ri_rate;
	uint32_t ri_antenna;
} __packed;

///////////////////////////////////////////////////////////////////////////////

struct air_wi
{
    int fd_in;
    int fd_out;
};

static struct air_wi g_air_wi = {0};

static unsigned char g_r_smac[6] = {0xCC, 0xDD,0xEE, 0xFF, 0x11, 0x22};

///////////////////////////////////////////////////////////////////////////////

unsigned long calc_crc_osdep(unsigned char * buf, int len)
{
	unsigned long crc = 0xFFFFFFFF;

	for (; len > 0; len--, buf++)
		crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

	return (~crc);
}

void __dump_data(unsigned char *ptr, int len, const char *info_fmt, ...)
{
    va_list ap;
    int i;

    printf("\n************************\n");
    printf("dump [");
    va_start(ap, info_fmt);
    vprintf(info_fmt, ap);
    va_end(ap);
    printf("]\n");

    for (i = 0; i < len; i++) {
        if (!(i%16))
            printf("\n %04x", i);
        printf(" %02x", ptr[i]);
    }
    printf("\n************************\n");
}

///////////////////////////////////////////////////////////////////////////////

/* CRC checksum verification routine */

int check_crc_buf_osdep(unsigned char * buf, int len)
{
	unsigned long crc;

	if (len < 0) return 0;

	crc = calc_crc_osdep(buf, len);
	buf += len;
	return (((crc) &0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1]
			&& ((crc >> 16) & 0xFF) == buf[2]
			&& ((crc >> 24) & 0xFF) == buf[3]);
}

int handle_w_data(unsigned char *data, int caplen, struct rx_info *ri)
{
	int n, got_signal, got_noise, got_channel, fcs_removed;

	n = got_signal = got_noise = got_channel = fcs_removed = 0;
    //if (dev->arptype_in == ARPHRD_IEEE80211_FULL)
    {
        struct ieee80211_radiotap_iterator iterator;
        struct ieee80211_radiotap_header * rthdr;

        rthdr = (struct ieee80211_radiotap_header *) data;

        if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen, NULL)
                < 0)
            return (0);

        /* go through the radiotap arguments we have been given
         * by the driver
         */

        while (ri && (ieee80211_radiotap_iterator_next(&iterator) >= 0))
        {

            switch (iterator.this_arg_index)
            {

                case IEEE80211_RADIOTAP_TSFT:
                    ri->ri_mactime
                        = le64_to_cpu(*((uint64_t *) iterator.this_arg));
                    break;

                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    if (!got_signal)
                    {
                        if (*iterator.this_arg < 127)
                            ri->ri_power = *iterator.this_arg;
                        else
                            ri->ri_power = *iterator.this_arg - 255;

                        got_signal = 1;
                    }
                    break;

                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                    if (!got_signal)
                    {
                        if (*iterator.this_arg < 127)
                            ri->ri_power = *iterator.this_arg;
                        else
                            ri->ri_power = *iterator.this_arg - 255;

                        got_signal = 1;
                    }
                    break;

                case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                    if (!got_noise)
                    {
                        if (*iterator.this_arg < 127)
                            ri->ri_noise = *iterator.this_arg;
                        else
                            ri->ri_noise = *iterator.this_arg - 255;

                        got_noise = 1;
                    }
                    break;

                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                    if (!got_noise)
                    {
                        if (*iterator.this_arg < 127)
                            ri->ri_noise = *iterator.this_arg;
                        else
                            ri->ri_noise = *iterator.this_arg - 255;

                        got_noise = 1;
                    }
                    break;

                case IEEE80211_RADIOTAP_ANTENNA:
                    ri->ri_antenna = *iterator.this_arg;
                    break;

                case IEEE80211_RADIOTAP_CHANNEL:
                    ri->ri_channel = getChannelFromFrequency(
                            le16toh(*(uint16_t *) iterator.this_arg));
                    got_channel = 1;
                    break;

                case IEEE80211_RADIOTAP_RATE:
                    ri->ri_rate = (*iterator.this_arg) * 500000;
                    break;

                case IEEE80211_RADIOTAP_FLAGS:
                    /* is the CRC visible at the end?
                     * remove
                     */
                    if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS)
                    {
                        fcs_removed = 1;
                        caplen -= 4;
                    }

                    if (*iterator.this_arg & IEEE80211_RADIOTAP_F_BADFCS)
                        return (0);

                    break;
            }
        }

        n = le16_to_cpu(rthdr->it_len);

        if (n <= 0 || n >= caplen) return (0);
    }
    
	caplen -= n;

	// detect fcs at the end, even if the flag wasn't set and remove it
	if (fcs_removed == 0 && check_crc_buf_osdep(data + n, caplen - 4) == 1)
	{
		caplen -= 4;
        n += 4;
	}

    //return caplen;
    return n;
}

int ieee80211_parse_beacon(const struct ieee80211_frame *wh, int frame_length)
{
#define BEACON_INFO_ELEMENT_OFFSET    (offsetof(struct ieee80211_beacon_frame, info_elements))

    unsigned int remaining_ie_length = 0;
    struct ieee80211_beacon_frame  *beacon_frame = (struct ieee80211_beacon_frame *)&(wh[1]);
    struct ieee80211_ie_header     *info_element = NULL;
    int beacon_length = frame_length - sizeof(struct ieee80211_frame);

    if (beacon_length < 0) {
        AIR_ERR("beacon_length is invalid.");
        return -1;
    }

    info_element = &(beacon_frame->info_elements);
    remaining_ie_length = beacon_length - BEACON_INFO_ELEMENT_OFFSET;

    /* Walk through to check nothing is malformed */
    while (remaining_ie_length >= sizeof(struct ieee80211_ie_header)) {
        /* At least one more header is present */
        remaining_ie_length -= sizeof(struct ieee80211_ie_header);

        if (info_element->length == 0) {
            info_element += 1;    /* next IE */
            continue;
        }

        if (remaining_ie_length < info_element->length) {
            /* Incomplete/bad info element */
            return -EINVAL;
        }

        //AIR_LOG("e id : %d", info_element->element_id);
        char _ssid[32];
        
        /* New info_element needs also be added in ieee80211_scan_entry_update */
        switch (info_element->element_id) {
            case IEEE80211_ELEMID_SSID:
                snprintf(_ssid, info_element->length + 1, "%s", (char *)(info_element + 1));
                AIR_LOG("ssid = %s", _ssid);
                break;
        }

        /* Consume info element */
        remaining_ie_length -= info_element->length;

        /* Go to next IE */
        info_element = (struct ieee80211_ie_header *)
            (((u_int8_t *) info_element) + sizeof(struct ieee80211_ie_header) + info_element->length);
    }


    return 0;
}

int raw_read(void)
{
    int len = 0;
    unsigned char buf[4096];
    int t_n =100;
    struct rx_info ri;
    struct ieee80211_frame *wh = NULL;
    int radio_tab_size = 0;

    int type = -1, subtype, dir;

    while (t_n) {
        memset(buf, 0, sizeof(buf));
        len = read(g_air_wi.fd_in, buf, sizeof(buf));
        //AIR_LOG("len = %d", len);
        radio_tab_size = handle_w_data(buf, len, &ri);
        //printf("power = %d, channel = %d\n", ri.ri_power, ri.ri_channel);
        wh = (struct ieee80211_frame *)((char *)buf + radio_tab_size);
        //printf("DST:"MAC_FMT"\n", MAC_PRINT(wh->i_addr1));
        type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
        dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

        if (type == IEEE80211_FC0_TYPE_MGT) {
            if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
                if (!memcmp(g_r_smac, wh->i_addr1, IEEE80211_ADDR_LEN)) {
                    AIR_LOG("GOT PROBE_RESP");
                    ieee80211_parse_beacon(wh, len);
                }
                t_n--;
            }
        }

    }

    return 0;
}

int raw_write(unsigned char *buf, int count)
{
    int ret = -1;
    unsigned int rate = 0;
	unsigned char tmpbuf[4096];
    int radiotab_len = 0;
    struct ieee80211_radiotap_header *r_hdr = NULL;

    #if 0
    //00 00 00 00  04 80 00 00  00 00 18 00  00 00
    //00 00 00 00  04 80 00 00  00 00 18 00
	unsigned char u8aRadiotap[] = {
		0x00,
		0x00, // <-- radiotap version
		0x0c,
		0x00, // <- radiotap header length

		0x04,
		0x80,
		0x00,
		0x00, // <-- bitmap

		0x00, // <-- rate
		0x00, // <-- padding for natural alignment
		0x18,
		0x00, // <-- TX flags
	};

    radiotab_len = sizeof(u8aRadiotap);
    rate = 2 * 500000;
	u8aRadiotap[8] = rate;
    memset(tmpbuf, 0, sizeof(tmpbuf));
    memcpy(tmpbuf, u8aRadiotap, radiotab_len);

    __dump_data((unsigned char *)tmpbuf, radiotab_len, "RadioTab");
    #else

    int pad = 0;
    unsigned char *pos = NULL;
    struct radiotap_align_size *as =NULL;

    memset(tmpbuf, 0, sizeof(tmpbuf));

    r_hdr = (struct ieee80211_radiotap_header *)tmpbuf;
    r_hdr->it_present = 
        cpu_to_le32((1 << IEEE80211_RADIOTAP_RATE) |
                (1 << IEEE80211_RADIOTAP_TX_FLAGS));

#define __PAD \
    pad = 0; \
    as = ieee80211_radiotap_get_align_size(IEEE80211_RADIOTAP_TX_FLAGS); \
    if (as->align > 1) { \
        if (radiotab_len % as->align != 0) { \
            pad = as->align - (radiotab_len % as->align); \
            pos += pad; \
            radiotab_len += pad; \
        } \
    }

    //rate = 2 * 500000 * 6;
    rate = (2 * 54); //* 500 000
    pos = (unsigned char *)(r_hdr + 1);
    radiotab_len += sizeof(struct ieee80211_radiotap_header);
    
    *pos = rate;
    pos += 1;
    radiotab_len += 1;
    
    __PAD;
    put_unaligned_le16(0x18, pos);
    pos += as->size;
    radiotab_len += as->size;
    r_hdr->it_len = radiotab_len;

    __dump_data((unsigned char *)r_hdr, radiotab_len, "RadioTab");
    #endif

   
    count += radiotab_len;
    memcpy(tmpbuf + radiotab_len, buf, count);
    buf = tmpbuf;

    AIR_LOG("len = %d", count);

	ret = write(g_air_wi.fd_out, buf, count);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS
			|| errno == ENOMEM) {
			usleep(10000);
			return 0;
		}

        AIR_ERR("errno = %d", errno);
		perror("write failed");
		return -1;
	}

    return 0;
}

int open_raw(const char *iface, int fd)
{

	struct ifreq ifr;
	struct sockaddr_ll sll;

	/* find the interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		AIR_ERR("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFINDEX) failed");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		AIR_ERR("Interface %s: \n", iface);
		perror("bind(ETH_P_ALL) failed");
		return -1;
	}

    return 0;
}

int create_sock(const char *iface)
{
    int fd = -1;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        AIR_LOG("socket failed.");
        return -1;
    }

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

	/* lookup the hardware type */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		AIR_ERR("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFHWADDR) failed");
        return -1;
	}

    /*
	if ((ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211
		 && ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM
		 && ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL)
		|| (wrq.u.mode != IW_MODE_MONITOR))
        */
	AIR_LOG("sa_family = %d", ifr.ifr_hwaddr.sa_family);

	struct iwreq wrq;

	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, iface, IFNAMSIZ);
	wrq.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(fd, SIOCGIWMODE, &wrq) < 0)
	{
	}
    //wrq.u.mode = IW_MODE_MONITOR;
    AIR_LOG("mode = %d", wrq.u.mode);
    if (wrq.u.mode != IW_MODE_MONITOR) {
        AIR_ERR("iface[%s] is not monitor mode!", iface);
    } else {
        AIR_LOG("iface[%s] is monitor mode!", iface);
    }


    //close(fd);
    //fd = -1;

    return fd;
}

int set_channel(const char *ifname, int channel)
{
    int skfd = -1;
    struct iwreq wrq;

    if((skfd = iw_sockets_open()) < 0) {
        AIR_ERR("iw sockets open failed.");
        return -1;
    }

    wrq.u.freq.flags = IW_FREQ_FIXED;
    iw_float2freq(channel, &(wrq.u.freq));

    if(iw_set_ext(skfd, ifname, SIOCSIWFREQ, &wrq) < 0) {
        return -1;
    }


    iw_sockets_close(skfd);
    skfd = -1;

    return 0;
}

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"
#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

static int send_probe_request(void)
{
	int len;
	unsigned char p[4096] = {0};
	//unsigned char r_smac[6] = {0xCC, 0xDD,0xEE, 0xFF, 0x11, 0x22};

	memcpy(p, PROBE_REQ, 24);

	len = 24;

	p[24] = 0x00; // ESSID Tag Number
	p[25] = 0x00; // ESSID Tag Length

	len += 2;

	memcpy(p + len, RATES, 16);

	len += 16;

    #if 0
	r_smac[0] = 0x00;
	r_smac[1] = rand() & 0xFF;
	r_smac[2] = rand() & 0xFF;
	r_smac[3] = rand() & 0xFF;
	r_smac[4] = rand() & 0xFF;
	r_smac[5] = rand() & 0xFF;
    #endif

	memcpy(p + 10, g_r_smac, 6);

	if (raw_write(p, len) == -1)
	{
		switch (errno) {
			case EAGAIN:
			case ENOBUFS:
				usleep(10000);
				return 0; /* XXX not sure I like this... -sorbo */
		}

		return -1;
	}

	return 0;
}

void *read_thread(void *arg)
{
    raw_read();

    return NULL;
}

int main(void)
{
    set_channel("wls35u1mon", 1);
    
    g_air_wi.fd_in = create_sock("wls35u1mon");
    g_air_wi.fd_out = create_sock("wls35u1mon");
    open_raw("wls35u1mon", g_air_wi.fd_out);


    pthread_t r_tid;
	pthread_attr_t thrd_Attr;

	pthread_attr_init(&thrd_Attr);
	pthread_attr_setdetachstate(&thrd_Attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&r_tid, NULL, read_thread, NULL);

    while (1) {
        send_probe_request();
        while (1) {
            sleep(1);
        }
    }

    close(g_air_wi.fd_in);
    close(g_air_wi.fd_out);
    g_air_wi.fd_in = -1;
    g_air_wi.fd_out = -1;

    return 0;
}
