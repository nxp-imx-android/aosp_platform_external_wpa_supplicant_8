/* Driver interaction with QEMU virtio wifi
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
*/

#ifndef DRIVER_VIRTIO_WIFI_H
#define DRIVER_VIRTIO_WIFI_H

extern void set_virtio_sock(int sock);
extern void set_virtio_ctl_sock(int sock);
struct hostapd_data;

struct virtio_wifi_data {
	struct hostapd_data *hapd;
	int sock; /* raw packet socket */
	int ioctl_sock; /* control cmds socket */
	u8 perm_addr[ETH_ALEN];
};

#endif
