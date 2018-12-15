#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/wireless.h>

#include "osdep/byteorder.h"
#include "osdep/common.h"
#include "osdep/crctable_osdep.h"

#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"

#include "lib/iwlib.h"

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

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif /* __packed */


#define IEEE80211_ADDR_LEN 6

struct ieee80211_frame {
    u_int8_t    i_fc[2];
    u_int8_t    i_dur[2];
    union {
        struct {
            u_int8_t    i_addr1[IEEE80211_ADDR_LEN];
            u_int8_t    i_addr2[IEEE80211_ADDR_LEN];
            u_int8_t    i_addr3[IEEE80211_ADDR_LEN];
        };
        u_int8_t    i_addr_all[3 * IEEE80211_ADDR_LEN];
    };
    u_int8_t    i_seq[2];
    /* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
    /* see below */
} __packed;

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

int g_raw_sk_fd = -1;


///////////////////////////////////////////////////////////////////////////////

unsigned long calc_crc_osdep(unsigned char * buf, int len)
{
	unsigned long crc = 0xFFFFFFFF;

	for (; len > 0; len--, buf++)
		crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

	return (~crc);
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

int raw_read(void)
{
    int len = 0;
    unsigned char buf[4096];
    int t_n =100;
    struct rx_info ri;
    struct ieee80211_frame *wh = NULL;
    int radio_tab_size = 0;

    while (t_n--) {
        memset(buf, 0, sizeof(buf));
        len = read(g_raw_sk_fd, buf, sizeof(buf));
        //AIR_LOG("len = %d", len);
        radio_tab_size = handle_w_data(buf, len, &ri);
        printf("power = %d, channel = %d\n", ri.ri_power, ri.ri_channel);
        wh = (struct ieee80211_frame *)((char *)buf + radio_tab_size);
        printf("DST:"MAC_FMT"\n", MAC_PRINT(wh->i_addr1));
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

int main(void)
{
    set_channel("wls35u1mon", 6);
    
    g_raw_sk_fd = create_sock("wls35u1mon");

    raw_read();

    close(g_raw_sk_fd);
    g_raw_sk_fd = -1;

    return 0;
}
