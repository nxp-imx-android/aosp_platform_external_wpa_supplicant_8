/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <algorithm>

#include <hidl/IServiceManager.h>

#include "hidl_constants.h"
#include "hidl_manager.h"
#include "wpa_supplicant_hidl/hidl_constants.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
}

namespace wpa_supplicant_hidl {

HidlManager *HidlManager::instance_ = NULL;

HidlManager *HidlManager::getInstance()
{
	if (!instance_)
		instance_ = new HidlManager();
	return instance_;
}

void HidlManager::destroyInstance()
{
	if (instance_)
		delete instance_;
	instance_ = NULL;
}

int HidlManager::registerHidlService(struct wpa_global *global)
{
	// Create the main hidl service object and register with system
	// ServiceManager.
	supplicant_object_ = new Supplicant(global);

	android::String16 service_name(hidl_constants::kServiceName);
	android::defaultServiceManager()->addService(
	    service_name, android::IInterface::asHidl(supplicant_object_));
	return 0;
}

/**
 * Register an interface to hidl manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::registerInterface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return 1;

	// Using the corresponding ifname as key to our object map.
	const std::string ifname(wpa_s->ifname);

	// Return failure if we already have an object for that |ifname|.
	if (iface_object_map_.find(ifname) != iface_object_map_.end())
		return 1;

	iface_object_map_[ifname] = new Iface(wpa_s->global, wpa_s->ifname);
	if (!iface_object_map_[ifname].get())
		return 1;

	// Initialize the vector of callbacks for this object.
	iface_callbacks_map_[ifname] =
	    std::vector<android::sp<fi::w1::wpa_supplicant::IIfaceCallback>>();

	// Invoke the |OnInterfaceCreated| method on all registered callbacks.
	callWithEachSupplicantCallback(std::bind(
	    &fi::w1::wpa_supplicant::ISupplicantCallback::OnInterfaceCreated,
	    std::placeholders::_1, ifname));
	return 0;
}

/**
 * Unregister an interface from hidl manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::unregisterInterface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return 1;

	const std::string ifname(wpa_s->ifname);

	if (iface_object_map_.find(ifname) == iface_object_map_.end())
		return 1;

	// Delete the corresponding iface object from our map.
	iface_object_map_.erase(ifname);

	// Delete all callbacks registered for this object.
	auto iface_callback_map_iter = iface_callbacks_map_.find(ifname);
	if (iface_callback_map_iter == iface_callbacks_map_.end())
		return 1;
	const auto &iface_callback_list = iface_callback_map_iter->second;
	for (const auto &callback : iface_callback_list) {
		if (android::IInterface::asHidl(callback)->unlinkToDeath(
			nullptr, callback.get()) != android::OK) {
			wpa_printf(
			    MSG_ERROR,
			    "Error deregistering for death notification for "
			    "iface callback object");
		}
	}
	iface_callbacks_map_.erase(iface_callback_map_iter);

	// Invoke the |OnInterfaceRemoved| method on all registered callbacks.
	callWithEachSupplicantCallback(std::bind(
	    &fi::w1::wpa_supplicant::ISupplicantCallback::OnInterfaceRemoved,
	    std::placeholders::_1, ifname));
	return 0;
}

/**
 * Register a network to hidl manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the network is added.
 * @param ssid |wpa_ssid| struct corresponding to the network being added.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::registerNetwork(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !ssid)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(wpa_s->ifname, ssid->id);

	if (network_object_map_.find(network_key) != network_object_map_.end())
		return 1;

	network_object_map_[network_key] =
	    new Network(wpa_s->global, wpa_s->ifname, ssid->id);
	if (!network_object_map_[network_key].get())
		return 1;

	// Initialize the vector of callbacks for this object.
	network_callbacks_map_[network_key] = std::vector<
	    android::sp<fi::w1::wpa_supplicant::INetworkCallback>>();

	// Invoke the |OnNetworkAdded| method on all registered callbacks.
	callWithEachIfaceCallback(
	    wpa_s->ifname,
	    std::bind(
		&fi::w1::wpa_supplicant::IIfaceCallback::OnNetworkAdded,
		std::placeholders::_1, ssid->id));
	return 0;
}

/**
 * Unregister a network from hidl manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the network is added.
 * @param ssid |wpa_ssid| struct corresponding to the network being added.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::unregisterNetwork(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !ssid)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(wpa_s->ifname, ssid->id);

	if (network_object_map_.find(network_key) == network_object_map_.end())
		return 1;

	// Delete the corresponding network object from our map.
	network_object_map_.erase(network_key);

	// Delete all callbacks registered for this object.
	auto network_callback_map_iter =
	    network_callbacks_map_.find(network_key);
	if (network_callback_map_iter == network_callbacks_map_.end())
		return 1;
	const auto &network_callback_list = network_callback_map_iter->second;
	for (const auto &callback : network_callback_list) {
		if (android::IInterface::asHidl(callback)->unlinkToDeath(
			nullptr, callback.get()) != android::OK) {
			wpa_printf(
			    MSG_ERROR,
			    "Error deregistering for death "
			    "notification for "
			    "network callback object");
		}
	}
	network_callbacks_map_.erase(network_callback_map_iter);

	// Invoke the |OnNetworkRemoved| method on all registered callbacks.
	callWithEachIfaceCallback(
	    wpa_s->ifname,
	    std::bind(
		&fi::w1::wpa_supplicant::IIfaceCallback::OnNetworkRemoved,
		std::placeholders::_1, ssid->id));
	return 0;
}

/**
 * Notify all listeners about any state changes on a particular interface.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the state change event occured.
 */
int HidlManager::notifyStateChange(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return 1;

	const std::string ifname(wpa_s->ifname);
	if (iface_object_map_.find(ifname) == iface_object_map_.end())
		return 1;

	// Invoke the |OnStateChanged| method on all registered callbacks.
	int state = wpa_s->wpa_state;
	std::vector<uint8_t> bssid(wpa_s->bssid, wpa_s->bssid + ETH_ALEN);
	int network_id =
	    fi::w1::wpa_supplicant::IIfaceCallback::NETWORK_ID_INVALID;
	std::vector<uint8_t> ssid;
	if (wpa_s->current_ssid) {
		network_id = wpa_s->current_ssid->id;
		ssid.assign(
		    wpa_s->current_ssid->ssid,
		    wpa_s->current_ssid->ssid + wpa_s->current_ssid->ssid_len);
	}
	callWithEachIfaceCallback(
	    wpa_s->ifname,
	    std::bind(
		&fi::w1::wpa_supplicant::IIfaceCallback::OnStateChanged,
		std::placeholders::_1, state, bssid, network_id, ssid));
	return 0;
}

/**
 * Notify all listeners about a request on a particular network.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the network is present.
 * @param ssid |wpa_ssid| struct corresponding to the network.
 * @param type type of request.
 * @param param addition params associated with the request.
 */
int HidlManager::notifyNetworkRequest(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid, int type,
    const char *param)
{
	if (!wpa_s || !ssid)
		return 1;

	const std::string network_key =
	    getNetworkObjectMapKey(wpa_s->ifname, ssid->id);
	if (network_object_map_.find(network_key) == network_object_map_.end())
		return 1;

	callWithEachNetworkCallback(
	    wpa_s->ifname, ssid->id,
	    std::bind(
		&fi::w1::wpa_supplicant::INetworkCallback::OnNetworkRequest,
		std::placeholders::_1, type, param));
	return 0;
}

/**
 * Retrieve the |IIface| hidl object reference using the provided
 * ifname.
 *
 * @param ifname Name of the corresponding interface.
 * @param iface_object Hidl reference corresponding to the iface.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::getIfaceHidlObjectByIfname(
    const std::string &ifname,
    android::sp<fi::w1::wpa_supplicant::IIface> *iface_object)
{
	if (ifname.empty() || !iface_object)
		return 1;

	auto iface_object_iter = iface_object_map_.find(ifname);
	if (iface_object_iter == iface_object_map_.end())
		return 1;

	*iface_object = iface_object_iter->second;
	return 0;
}

/**
 * Retrieve the |INetwork| hidl object reference using the provided
 * ifname and network_id.
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 * @param network_object Hidl reference corresponding to the network.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::getNetworkHidlObjectByIfnameAndNetworkId(
    const std::string &ifname, int network_id,
    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object)
{
	if (ifname.empty() || network_id < 0 || !network_object)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(ifname, network_id);

	auto network_object_iter = network_object_map_.find(network_key);
	if (network_object_iter == network_object_map_.end())
		return 1;

	*network_object = network_object_iter->second;
	return 0;
}

/**
 * Add a new |ISupplicantCallback| hidl object reference to our
 * global callback list.
 *
 * @param callback Hidl reference of the |ISupplicantCallback| object.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::addSupplicantCallbackHidlObject(
    const android::sp<fi::w1::wpa_supplicant::ISupplicantCallback> &callback)
{
	// Register for death notification before we add it to our list.
	auto on_hidl_died_fctor = std::bind(
	    &HidlManager::removeSupplicantCallbackHidlObject, this,
	    std::placeholders::_1);
	return registerForDeathAndAddCallbackHidlObjectToList<
	    fi::w1::wpa_supplicant::ISupplicantCallback>(
	    callback, on_hidl_died_fctor, supplicant_callbacks_);
}
/**
 * Add a new |IIfaceCallback| hidl object reference to our
 * interface callback list.
 *
 * @param ifname Name of the corresponding interface.
 * @param callback Hidl reference of the |IIfaceCallback| object.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::addIfaceCallbackHidlObject(
    const std::string &ifname,
    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback> &callback)
{
	if (ifname.empty())
		return 1;

	auto iface_callback_map_iter = iface_callbacks_map_.find(ifname);
	if (iface_callback_map_iter == iface_callbacks_map_.end())
		return 1;
	auto &iface_callback_list = iface_callback_map_iter->second;

	// Register for death notification before we add it to our list.
	auto on_hidl_died_fctor = std::bind(
	    &HidlManager::removeIfaceCallbackHidlObject, this, ifname,
	    std::placeholders::_1);
	return registerForDeathAndAddCallbackHidlObjectToList<
	    fi::w1::wpa_supplicant::IIfaceCallback>(
	    callback, on_hidl_died_fctor, iface_callback_list);
}

/**
 * Add a new |INetworkCallback| hidl object reference to our
 * network callback list.
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 * @param callback Hidl reference of the |INetworkCallback| object.
 *
 * @return 0 on success, 1 on failure.
 */
int HidlManager::addNetworkCallbackHidlObject(
    const std::string &ifname, int network_id,
    const android::sp<fi::w1::wpa_supplicant::INetworkCallback> &callback)
{
	if (ifname.empty() || network_id < 0)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(ifname, network_id);
	auto network_callback_map_iter =
	    network_callbacks_map_.find(network_key);
	if (network_callback_map_iter == network_callbacks_map_.end())
		return 1;
	auto &network_callback_list = network_callback_map_iter->second;

	// Register for death notification before we add it to our list.
	auto on_hidl_died_fctor = std::bind(
	    &HidlManager::removeNetworkCallbackHidlObject, this, ifname,
	    network_id, std::placeholders::_1);
	return registerForDeathAndAddCallbackHidlObjectToList<
	    fi::w1::wpa_supplicant::INetworkCallback>(
	    callback, on_hidl_died_fctor, network_callback_list);
}

/**
 * Creates a unique key for the network using the provided |ifname| and
 * |network_id| to be used in the internal map of |INetwork| objects.
 * This is of the form |ifname|_|network_id|. For ex: "wlan0_1".
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 */
const std::string HidlManager::getNetworkObjectMapKey(
    const std::string &ifname, int network_id)
{
	return ifname + "_" + std::to_string(network_id);
}

/**
 * Removes the provided |ISupplicantCallback| hidl object reference
 * from our global callback list.
 *
 * @param callback Hidl reference of the |ISupplicantCallback| object.
 */
void HidlManager::removeSupplicantCallbackHidlObject(
    const android::sp<fi::w1::wpa_supplicant::ISupplicantCallback> &callback)
{
	supplicant_callbacks_.erase(
	    std::remove(
		supplicant_callbacks_.begin(), supplicant_callbacks_.end(),
		callback),
	    supplicant_callbacks_.end());
}

/**
 * Removes the provided |IIfaceCallback| hidl object reference from
 * our interface callback list.
 *
 * @param ifname Name of the corresponding interface.
 * @param callback Hidl reference of the |IIfaceCallback| object.
 */
void HidlManager::removeIfaceCallbackHidlObject(
    const std::string &ifname,
    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback> &callback)
{
	if (ifname.empty())
		return;

	auto iface_callback_map_iter = iface_callbacks_map_.find(ifname);
	if (iface_callback_map_iter == iface_callbacks_map_.end())
		return;

	auto &iface_callback_list = iface_callback_map_iter->second;
	iface_callback_list.erase(
	    std::remove(
		iface_callback_list.begin(), iface_callback_list.end(),
		callback),
	    iface_callback_list.end());
}

/**
 * Removes the provided |INetworkCallback| hidl object reference from
 * our network callback list.
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 * @param callback Hidl reference of the |INetworkCallback| object.
 */
void HidlManager::removeNetworkCallbackHidlObject(
    const std::string &ifname, int network_id,
    const android::sp<fi::w1::wpa_supplicant::INetworkCallback> &callback)
{
	if (ifname.empty() || network_id < 0)
		return;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(ifname, network_id);

	auto network_callback_map_iter =
	    network_callbacks_map_.find(network_key);
	if (network_callback_map_iter == network_callbacks_map_.end())
		return;

	auto &network_callback_list = network_callback_map_iter->second;
	network_callback_list.erase(
	    std::remove(
		network_callback_list.begin(), network_callback_list.end(),
		callback),
	    network_callback_list.end());
}

/**
 * Add callback to the corresponding list after linking to death on the
 * corresponding hidl object reference.
 *
 * @param callback Hidl reference of the |INetworkCallback| object.
 *
 * @return 0 on success, 1 on failure.
 */
template <class CallbackType>
int HidlManager::registerForDeathAndAddCallbackHidlObjectToList(
    const android::sp<CallbackType> &callback,
    const std::function<void(const android::sp<CallbackType> &)>
	&on_hidl_died_fctor,
    std::vector<android::sp<CallbackType>> &callback_list)
{
	auto death_notifier = new CallbackObjectDeathNotifier<CallbackType>(
	    callback, on_hidl_died_fctor);
	// Use the |callback.get()| as cookie so that we don't need to
	// store a reference to this |CallbackObjectDeathNotifier| instance
	// to use in |unlinkToDeath| later.
	// NOTE: This may cause an immediate callback if the object is already
	// dead,
	// so add it to the list before we register for callback!
	callback_list.push_back(callback);
	if (android::IInterface::asHidl(callback)->linkToDeath(
		death_notifier, callback.get()) != android::OK) {
		wpa_printf(
		    MSG_ERROR,
		    "Error registering for death notification for "
		    "supplicant callback object");
		callback_list.erase(
		    std::remove(
			callback_list.begin(), callback_list.end(), callback),
		    callback_list.end());
		return 1;
	}
	return 0;
}

/**
 * Helper function to invoke the provided callback method on all the
 * registered |ISupplicantCallback| callback hidl objects.
 *
 * @param method Pointer to the required hidl method from
 * |ISupplicantCallback|.
 */
void HidlManager::callWithEachSupplicantCallback(
    const std::function<android::hidl::Status(
	android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>)> &method)
{
	for (const auto &callback : supplicant_callbacks_) {
		method(callback);
	}
}

/**
 * Helper fucntion to invoke the provided callback method on all the
 * registered |IIfaceCallback| callback hidl objects for the specified
 * |ifname|.
 *
 * @param ifname Name of the corresponding interface.
 * @param method Pointer to the required hidl method from |IIfaceCallback|.
 */
void HidlManager::callWithEachIfaceCallback(
    const std::string &ifname,
    const std::function<android::hidl::Status(
	android::sp<fi::w1::wpa_supplicant::IIfaceCallback>)> &method)
{
	if (ifname.empty())
		return;

	auto iface_callback_map_iter = iface_callbacks_map_.find(ifname);
	if (iface_callback_map_iter == iface_callbacks_map_.end())
		return;
	const auto &iface_callback_list = iface_callback_map_iter->second;
	for (const auto &callback : iface_callback_list) {
		method(callback);
	}
}

/**
 * Helper function to invoke the provided callback method on all the
 * registered |INetworkCallback| callback hidl objects for the specified
 * |ifname| & |network_id|.
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 * @param method Pointer to the required hidl method from |INetworkCallback|.
 */
void HidlManager::callWithEachNetworkCallback(
    const std::string &ifname, int network_id,
    const std::function<android::hidl::Status(
	android::sp<fi::w1::wpa_supplicant::INetworkCallback>)> &method)
{
	if (ifname.empty() || network_id < 0)
		return;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(ifname, network_id);
	auto network_callback_map_iter =
	    network_callbacks_map_.find(network_key);
	if (network_callback_map_iter == network_callbacks_map_.end())
		return;
	const auto &network_callback_list = network_callback_map_iter->second;
	for (const auto &callback : network_callback_list) {
		method(callback);
	}
}
}  // namespace wpa_supplicant_hidl