/*
 * Driver interaction with QEMU virtio wifi
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "includes.h"

#include "android/utils/sockets.h"
#include "common.h"
#include "driver.h"
#include "driver_virtio_wifi.h"
#include "eloop.h"
#include "ap/hostapd.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"

#define IEEE80211_MAX_FRAME_LEN		2352

static void handle_data(struct virtio_wifi_data *drv, u8 *buf, size_t len,
			u16 stype)
{
	struct ieee80211_hdr *hdr;
	u16 fc, ethertype;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	if (len < sizeof(struct ieee80211_hdr))
		return;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	/*if ((fc & (WLAN_FC_FROMDS | WLAN_FC_TODS)) != WLAN_FC_TODS) {
		printf("Not ToDS data frame (fc=0x%04x)\n", fc);
		return;
	}*/

	sa = hdr->addr2;
	os_memset(&event, 0, sizeof(event));
	pos = (u8 *) (hdr + 1);
	left = len - sizeof(*hdr);
	if (left < 2) {
		printf("No ethertype in data frame\n");
		return;
	}
	ethertype = WPA_GET_BE16(pos);
	pos += 2;
	left -= 2;
	switch (ethertype) {
	case ETH_P_PAE:
		drv_event_eapol_rx(drv->hapd, sa, pos, left);
		break;

	default:
		printf("Unknown ethertype 0x%04x in data frame\n", ethertype);
		break;
	}
}

static void handle_tx_callback(struct virtio_wifi_data *drv, const u8 *buf,
			       size_t len, int ok)
{
	struct ieee80211_hdr *hdr;
	u16 fc;
	union wpa_event_data event;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	os_memset(&event, 0, sizeof(event));
	event.tx_status.type = WLAN_FC_GET_TYPE(fc);
	event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
	event.tx_status.dst = hdr->addr1;
	event.tx_status.data = buf;
	event.tx_status.data_len = len;
	event.tx_status.ack = ok;
	wpa_supplicant_event(drv->hapd, EVENT_TX_STATUS, &event);
}

static void handle_frame(struct virtio_wifi_data *drv, u8 *buf, size_t len)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	union wpa_event_data event;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		os_memset(&event, 0, sizeof(event));
		event.rx_mgmt.frame = buf;
		event.rx_mgmt.frame_len = len;
		wpa_supplicant_event(drv->hapd, EVENT_RX_MGMT, &event);
		break;
	case WLAN_FC_TYPE_DATA:
		handle_data(drv, buf, len, stype);
		break;
	case WLAN_FC_TYPE_CTRL:
		break;
	default:
		wpa_printf(MSG_ERROR, "unknown frame type %d \n",
			   type);
		break;
	}
}

static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct virtio_wifi_data *drv = eloop_ctx;
	int len;
	unsigned char buf[IEEE80211_MAX_FRAME_LEN];
	len = socket_recv(sock, buf, IEEE80211_MAX_FRAME_LEN);

	if (len < 0) {
		wpa_printf(MSG_ERROR, "recv: %s", strerror(errno));
		return;
	}
	handle_frame(drv, buf, len);
}

static const unsigned char s_bssid[] = {0x00, 0x13, 0x10, 0x85, 0xfe, 0x01};

static struct virtio_wifi_data * priv_drv = NULL;

void set_virtio_sock(int sock) {
	priv_drv->sock = sock;
	if (priv_drv->sock != -1 && eloop_register_read_sock(priv_drv->sock, handle_read, priv_drv, NULL))
	{
		wpa_printf(MSG_INFO, "virtio wifi: Could not register read socket for eapol");
	}
}

void set_virtio_ctl_sock(int sock) {
	priv_drv->ioctl_sock = sock;
}

static void *virtio_wifi_init(struct hostapd_data *hapd,
		       struct wpa_init_params *params)
{
	struct virtio_wifi_data *drv;
	drv = os_zalloc(sizeof(*drv));
	priv_drv = drv;
	drv->hapd = hapd;
	os_memcpy(drv->perm_addr, s_bssid, ETH_ALEN);
	os_memcpy(hapd->own_addr, s_bssid, ETH_ALEN);
	return drv;
}

static void virtio_wifi_deinit(void *priv) {
	struct virtio_wifi_data *drv = priv;
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv->sock >= 0)
		close(drv->sock);
	free(drv);
}

static int virtio_wifi_send_mlme(void *priv, const u8 *msg, size_t len, int noack,
			    unsigned int freq,
			    const u16 *csa_offs, size_t csa_offs_len)
{
	struct virtio_wifi_data *drv = priv;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) msg;
	struct ieee80211_mgmt* mgmt = (struct ieee80211_mgmt *) msg;
	u16 fc = le_to_host16(mgmt->frame_control);
	int res;
	memcpy(hdr->IEEE80211_BSSID_FROMDS, priv_drv->hapd->own_addr, ETH_ALEN);
	memcpy(hdr->IEEE80211_SA_FROMDS, priv_drv->hapd->own_addr, ETH_ALEN);
	res = socket_send(drv->sock, msg, len);
	/* Request TX callback, assume that they have always been received */
	handle_tx_callback(drv, msg, len, 1);
	return res;
}

static int virtio_wifi_send_eapol(void *priv, const u8 *addr, const u8 *data,
			     size_t data_len, int encrypt, const u8 *own_addr,
			     u32 flags)
{
	struct virtio_wifi_data *drv = priv;
	struct ieee80211_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + 2 + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		printf("malloc() failed for hostapd_send_data(len=%lu)\n",
		       (unsigned long) len);
		return -1;
	}

	hdr->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_DATA);
	hdr->frame_control |= host_to_le16(WLAN_FC_FROMDS);
	if (encrypt)
		hdr->frame_control |= host_to_le16(WLAN_FC_ISWEP);
	memcpy(hdr->IEEE80211_DA_FROMDS, addr, ETH_ALEN);
	memcpy(hdr->IEEE80211_BSSID_FROMDS, own_addr, ETH_ALEN);
	memcpy(hdr->IEEE80211_SA_FROMDS, own_addr, ETH_ALEN);

	pos = (u8 *) (hdr + 1);
	*((u16 *) pos) = htons(ETH_P_PAE);
	pos += 2;
	memcpy(pos, data, data_len);

	res = virtio_wifi_send_mlme(drv, (u8 *) hdr, len, 0, 0, NULL, 0);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "hostap_send_eapol - packet len: %lu - "
			   "failed: %d (%s)",
			   (unsigned long) len, errno, strerror(errno));
	}
	os_free(hdr);
	return res;
}

static int virtio_wifi_if_add(void *priv, enum wpa_driver_if_type type,
				     const char *ifname, const u8 *addr,
				     void *bss_ctx, void **drv_priv,
				     char *force_ifname, u8 *if_addr,
				     const char *bridge, int use_existing,
				     int setup_ap)
{
	if (addr) {
		os_memcpy(if_addr, addr, ETH_ALEN);
	}
	return 0;
}

static struct hostapd_hw_modes * virtio_wifi_get_hw_feature_data(void *priv,
							    u16 *num_modes,
							    u16 *flags, u8 *dfs)
{
	struct hostapd_hw_modes *mode;
	int i, clen, rlen;
	const short chan2freq[14] = {
		2412, 2417, 2422, 2427, 2432, 2437, 2442,
		2447, 2452, 2457, 2462, 2467, 2472, 2484
	};

	mode = os_zalloc(sizeof(struct hostapd_hw_modes));
	if (mode == NULL)
		return NULL;

	*num_modes = 1;
	*flags = 0;
	*dfs = 0;

	mode->mode = HOSTAPD_MODE_IEEE80211G;
	mode->num_channels = 14;
	mode->num_rates = 4;

	clen = mode->num_channels * sizeof(struct hostapd_channel_data);
	rlen = mode->num_rates * sizeof(int);

	mode->channels = os_zalloc(clen);
	mode->rates = os_zalloc(rlen);
	if (mode->channels == NULL || mode->rates == NULL) {
		os_free(mode->channels);
		os_free(mode->rates);
		os_free(mode);
		return NULL;
	}

	for (i = 0; i < 14; i++) {
		mode->channels[i].chan = i + 1;
		mode->channels[i].freq = chan2freq[i];
		mode->channels[i].allowed_bw = HOSTAPD_CHAN_WIDTH_20;
		// TODO: Get allowed channel list from the driver 
		if (i >= 11)
			mode->channels[i].flag = HOSTAPD_CHAN_DISABLED;
	}

	mode->rates[0] = 10;
	mode->rates[1] = 20;
	mode->rates[2] = 55;
	mode->rates[3] = 110;

	return mode;
}

static const u8 * virtio_wifi_get_macaddr(void *priv)
{
	struct virtio_wifi_data *drv = priv;

	return drv->perm_addr;
}

const struct wpa_driver_ops wpa_driver_virtio_wifi_ops = {
	.name = "virtio_wifi",
	.desc = "Qemu virtio WiFi",
	.get_mac_addr = virtio_wifi_get_macaddr,
	.if_add = virtio_wifi_if_add,
	.get_hw_feature_data = virtio_wifi_get_hw_feature_data,
	.hapd_send_eapol = virtio_wifi_send_eapol,
	.send_mlme = virtio_wifi_send_mlme,
	.hapd_init = virtio_wifi_init,
	.hapd_deinit = virtio_wifi_deinit,
};