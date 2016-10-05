/* vim: set et: */
//FIXME: Multichannel auth functions!

BOOL prefix(const char *str, const char *pre)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

#define WLAN_NULL 0


enum wlan_security {
    WLAN_BASIC = 1,
    WLAN_WPA = 2,
    WLAN_11i = 4,
    WLAN_WPAand11i = 6
};

enum wlan_auth {
    WLAN_OPEN = 1,
    WLAN_PSK = 2,
    WLAN_EAP = 3,
    WLAN_SHARED = 4
};

enum wlan_encryption {
    WLAN_NO_ENCRYPTION = 1,
    WLAN_WEP = 2,
    WLAN_AES = 4,
    WLAN_TKIP = 8,
    WLAN_TKIPAES = 12
};

struct wlan_security_mode {
    enum wlan_security mode;
    enum wlan_auth authMode;
    enum wlan_encryption encrypt;
};

static void nvram_set_tuple(const char *key, unsigned index, const char *value)
{
    char *v = NULL;
    char *e = NULL;
    char *s = NULL;
    unsigned i = 0;
    char *nv = NULL;

    size_t vlen = 0u;
    size_t len = 0u;
    size_t value_len = strlen(value);

    /* indexes started at 1 */
    index++;

    e = s = v = cwmp_nvram_get(key);
    vlen = strlen(v);
    while ((e = strchr(s, ';')) != NULL) {
        if (++i == index)
            break;
        s = ++e;
    }
    /* fix endpos */
    if (!e) {
        e = v + vlen;
        i++;
    }

    if (i != index) {
        cwmp_log_info("%s: grow list from %u i to %u", __func__, i, index);
        i = index - i;
        s = e;
    } else {
        i = 0;
    }

    /* format new nvram value */
    len = vlen - (e - s) + value_len + i + 1;
    nv = calloc(1, len);
    if (!nv) {
        cwmp_log_error("%s: calloc(%"PRIuPTR") failed: %s",
                __func__,
                len, strerror(errno));
        return;
    }

    if (i) {
        snprintf(nv, len, "%s%*.0s%s", v, i, "", value);
        memset(nv + vlen, ';', i);
    } else {
        snprintf(nv, len, "%.*s%s%s", (s - v), v, value, e);
    }
    cwmp_nvram_set(key, nv);
    free(nv);

    return;
}

static size_t nvram_get_tuple(const char *key, unsigned index,
        char *value, size_t value_size)
{
    char *v = NULL;
    char *e = NULL;
    char *s = NULL;
    unsigned i = 0;
    size_t len = 0u;

    /* indexes started at 1 */
    index++;

    e = s = v = cwmp_nvram_get(key);
    len = strlen(v);
    while ((e = strchr(s, ';')) != NULL) {
        if (++i == index)
            break;
        /* next */
        s = ++e;
    }
    /* fix endpos */
    if (!e) {
        e = v + len;
        i++;
    }

    if (i != index) {
        s = e;
        cwmp_log_error("%s: invalid index: %u, maximum: %u",
                __func__, index, i);
    }

    memset(value, 0u, value_size);
    len = (e - s);
    if (len && value) {
        snprintf(value, value_size, "%.*s", len, s);
    }
    return len;
}

static void nvram_wlan_normalize(unsigned index, struct wlan_security_mode *wsm)
{
    if (wsm->mode == WLAN_BASIC) {
        /* normalization for Basic mode */
        if (wsm->authMode != WLAN_OPEN || wsm->authMode != WLAN_SHARED) {
            cwmp_log_info(
                    "WLANConfiguration: "
                    "set BasicAuthenticationMode to None for index %u", index);
            wsm->authMode = WLAN_OPEN;
        }
        if (wsm->encrypt != WLAN_NO_ENCRYPTION || wsm->encrypt != WLAN_WEP) {
            cwmp_log_info(
                    "WLANConfiguration: "
                    "set BasicEncryptionModes to None for index %u", index);
            wsm->encrypt = WLAN_NO_ENCRYPTION;
        }
    } else if (wsm->mode == WLAN_WPA ||
            wsm->mode == WLAN_11i ||
            wsm->mode == WLAN_WPAand11i) {
        /* WPA/WPA2 */
        const char *v = NULL;
        switch (wsm->mode) {
            case WLAN_WPA:
                v = "WPA";
                break;
            case WLAN_11i:
            case WLAN_WPAand11i:
                v = "IEEE11i";
                break;
            default:
                v = "";
        }
        if (wsm->authMode != WLAN_PSK || wsm->authMode != WLAN_EAP) {
            cwmp_log_info(
                    "WLANConfiguration: "
                    "set %sAuthenticationMode to PSKAuthentication for index %u", v, index);
            wsm->authMode = WLAN_PSK;
        }
        if (wsm->encrypt != WLAN_AES || wsm->encrypt != WLAN_TKIP || wsm->encrypt != WLAN_TKIPAES) {
            cwmp_log_info(
                    "WLANConfiguration: "
                    "set %sEncryptionModes to AESEncryption for index %u", v, index);
            wsm->encrypt = WLAN_AES;
        }
    } else {
        /* unknown? */
        wsm->mode = WLAN_BASIC;
        wsm->authMode = WLAN_OPEN;
        wsm->encrypt = WLAN_NO_ENCRYPTION;
        cwmp_log_info(
                "WLANConfiguration: "
                "BasicAuthenticationMode as default for index %u", index);
    }
}

static bool nvram_wlan_load(unsigned index, struct wlan_security_mode *wsm)
{
    char auth[128] = {};
    char encr[128] = {};
    if (!nvram_get_tuple("AuthMode", index, auth, sizeof(auth))) {
        cwmp_log_error("WLANConfiguration: undefined nvram's AuthMode value for index %u", index);
    }
    if (!nvram_get_tuple("EncrypType", index, encr, sizeof(encr))) {
        cwmp_log_error("WLANConfiguration: undefined nvram's EncrypType value for index %u", index);
    }

    /* load encryption */
    if (!strcmp(encr, "NONE")) {
        wsm->encrypt = WLAN_NO_ENCRYPTION;
    } else if(!strcmp(encr, "WEP")) {
        wsm->encrypt = WLAN_WEP;
    } else if (!strcmp(encr, "AES")) {
        wsm->encrypt = WLAN_AES;
    } else if (!strcmp(encr, "TKIP")) {
        wsm->encrypt = WLAN_TKIP;
    } else if (!strcmp(encr, "TKIPAES")) {
        wsm->encrypt = WLAN_TKIPAES;
    } else {
        cwmp_log_error(
            "WLANConfiguration: "
            "unknown nvram's EncrypType value for index %u: '%s'",
            index, auth);
    }

    /* load auth mode and security mode */
    if (!strcmp(auth, "OPEN")) {
        wsm->authMode = WLAN_OPEN;
        wsm->mode = WLAN_BASIC;
    } else if (!strcmp(auth, "SHARED")) {
        wsm->authMode = WLAN_SHARED;
        wsm->mode = WLAN_BASIC;
    } else if (!strcmp(auth, "WPA")) {
        wsm->authMode = WLAN_EAP;
        wsm->mode = WLAN_WPA;
    } else if (!strcmp(auth, "WPAPSK")) {
        wsm->authMode = WLAN_PSK;
        wsm->mode = WLAN_WPA;
    } else if(!strcmp(auth, "WPAPSKWPA2PSK")) {
        wsm->authMode = WLAN_PSK;
        wsm->mode = WLAN_WPAand11i;
    } else if (!strcmp(auth, "WPA1WPA2")) {
        wsm->authMode = WLAN_EAP;
        wsm->mode = WLAN_WPAand11i;
    } else if (!strcmp(auth, "WPA2")) {
        wsm->authMode = WLAN_EAP;
        wsm->mode = WLAN_11i;
    } else if (!strcmp(auth, "WPA2PSK")) {
        wsm->authMode = WLAN_PSK;
        wsm->mode = WLAN_11i;
    } else {
        wsm->authMode = WLAN_OPEN;
        wsm->mode = WLAN_BASIC;
        wsm->encrypt = WLAN_NO_ENCRYPTION;
        cwmp_log_error(
                "WLANConfiguration: "
                "unknown nvram's AuthMode value for index %u: '%s'",
                index, auth);
    }
    return true;
}

static bool nvram_wlan_save(unsigned index, struct wlan_security_mode *wsm)
{
    const char *auth = NULL;
    const char *encr = NULL;
    struct wlan_security_mode wsm_orig = {};
    nvram_wlan_load(index, &wsm_orig);

    /* merge */
    if (wsm->authMode != WLAN_NULL) {
        switch (wsm->authMode) {
            case WLAN_OPEN:
            case WLAN_SHARED:
                wsm->mode = WLAN_BASIC;
                break;
            case WLAN_PSK:
            case WLAN_EAP:
                wsm->mode = WLAN_WPAand11i;
                break;
        }
        wsm->encrypt = wsm_orig.encrypt;
    } else if (!wsm->encrypt != WLAN_NULL) {
        switch (wsm->encrypt) {
            case WLAN_NO_ENCRYPTION:
            case WLAN_WEP:
                wsm->mode = WLAN_BASIC;
            case WLAN_AES:
            case WLAN_TKIP:
            case WLAN_TKIPAES:
                wsm->mode = WLAN_WPAand11i;
        }
        wsm->authMode = wsm_orig.authMode;
    } else if (wsm->mode != WLAN_NULL) {
        wsm->encrypt = wsm_orig.encrypt;
        wsm->authMode = wsm_orig.authMode;
    }

    nvram_wlan_normalize(index, wsm);

    /* nvram AuthMode */
    switch (wsm->authMode) {
        case WLAN_OPEN:
            auth = "OPEN";
            break;
        case WLAN_SHARED:
            auth = "SHARED";
            break;
        case WLAN_PSK:
            if (wsm->mode == WLAN_WPA) {
                auth = "WPAPSK";
            } else if (wsm->mode == WLAN_11i) {
                auth = "WPA2PSK";
            } else if (wsm->mode == WLAN_WPAand11i) {
                auth = "WPAPSKWPA2PSK";
            }
            break;
        case WLAN_EAP:
            if (wsm->mode == WLAN_WPA) {
                auth = "WPA";
            } else if (wsm->mode == WLAN_11i) {
                auth = "WPA2";
            } else if (wsm->mode == WLAN_WPAand11i) {
                auth = "WPA1WPA2";
            }
            break;
    }
    /* nvram EncrypType */
    switch(wsm->encrypt) {
        case WLAN_NO_ENCRYPTION:
            encr = "NONE";
            break;
        case WLAN_WEP:
            encr = "WEP";
            break;
        case WLAN_AES:
            encr = "AES";
            break;
        case WLAN_TKIP:
            encr = "TKIP";
            break;
        case WLAN_TKIPAES:
            encr = "TKIPAES";
            break;
    }

    /* write */
    nvram_set_tuple("AuthMode", index, auth);
    nvram_set_tuple("EncrypType", index, encr);

    return true;
}

int cpe_get_igd_lan_wlan_bssid(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_bssid");
    char if_hw[18] = {0};

    char* ifstart = cwmp_nvram_pool_get(pool,"BssidIfName");
    char ifname[20] = {0};
    strcat(ifname,ifstart);
    strcat(ifname,args);

    if (getIfMac(ifname, if_hw, ':') == -1) *value = pool_pstrdup(pool,"00:00:00:00:00:00");
    else *value = pool_pstrdup(pool,if_hw);

    cwmp_log_debug("DEBUG cpe_get_igd_lan_wlan_bssid: BSSID%s %s",args,*value);

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_autochannel(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_autochannel");
    int chan =  cwmp_nvram_get_int("Channel", 0);
    int autoselect = cwmp_nvram_get_int("AutoChannelSelect",1);

    *value = pool_pstrdup(pool, ((chan==0) || autoselect)?"1":"0");

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_autochannel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_autochannel");
    if (value == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_autochannel: undefined value!");
	return FAULT_CODE_9002;
    }

    if (value[0] == '1') {
	cwmp_nvram_set("Channel","0");
	cwmp_nvram_set("AutoChannelSelect","1");
    }
    else
    {
        int chan =  cwmp_nvram_get_int("Channel", 0);
	cwmp_nvram_set("AutoChannelSelect","0");
	if (chan == 0) cwmp_nvram_set("Channel", "9");
    }

    return FAULT_CODE_OK;
}

int cpe_get_igd_lan_wlan_channel(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_channel");
    char* chan =  cwmp_nvram_pool_get(pool, "Channel");
    if (chan == NULL)
    {
	chan = "0";
    }

    int autoselect = cwmp_nvram_get_int("AutoChannelSelect",1);

    if (autoselect)
    {
	*value = pool_pstrdup(pool, "0");
    }
    else
    {
	*value = pool_pstrdup(pool, chan);
    }


    return FAULT_CODE_OK;

}

int cpe_set_igd_lan_wlan_channel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_channel");

    if (value == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_channel: undefined value!");
	return FAULT_CODE_9002;
    }

    cwmp_nvram_set("Channel",value);

    if (value[0] == '0' && value[1] == '\0') {
	cwmp_nvram_set("AutoChannelSelect", "1");
    }
    else
    {
	cwmp_nvram_set("AutoChannelSelect", "0");
    }

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_standard(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_standard");
    int standard =  cwmp_nvram_get_int("WirelessMode", 9);

    char* stdstr;

    switch (standard) {

	case 0: stdstr = "b/g/n";break;
	case 1: stdstr = "b";break;
	case 4: stdstr = "g";break;
	case 6: stdstr = "n";break;
	case 7: stdstr = "b/g/n";break;
	case 9: stdstr = "b/g/n";break;
	default: stdstr = "b/g/n";break;
    }

    *value = pool_pstrdup(pool, stdstr);
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_standard %s",stdstr);

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_standard(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    char* valStr = "9";

	DM_TRACE_SET();
    if (strcmp(value, "n") == 0) valStr="6";else
    if (strcmp(value, "g") == 0) valStr="4";else
    if (strcmp(value, "b") == 0) valStr="1";

    cwmp_nvram_set("WirelessMode", valStr);

    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_standard %s", valStr);

    return FAULT_CODE_OK;
}

/* BasicAuthenticationMode */
int cpe_get_igd_lan_wlan_basicauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

    DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    if (wsm.mode != WLAN_BASIC) {
        *value = "None";
        return FAULT_CODE_OK;
    }

    switch (wsm.authMode) {
        case WLAN_OPEN:
            *value = "None";
            break;
        case WLAN_SHARED:
            *value = "SharedAuthentication";
            break;
        case WLAN_EAP:
            *value = "EAPAuthentication";
            break;
        default:
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_basicauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};
    DM_TRACE_SET();

    if (!strcmp(value,"None")) {
        /* Open */
        wsm.authMode = WLAN_OPEN;
    } else if (!strcmp(value, "SharedAuthentication")) {
        /* Shared */
        wsm.authMode = WLAN_SHARED;
    } else if (!strcmp(value, "EAPAuthentication")) {
        /* not supported */
        cwmp_log_info("%s: (index %u) Radius auth not supported");
        wsm.authMode = WLAN_OPEN;
    } else {
        cwmp_log_error("%s: (index %u) invalid value: '%s'",
                __func__, index, value);
        return FAULT_CODE_9007;
    }
    nvram_wlan_save(index, &wsm);

    return FAULT_CODE_OK;
}

/* BasicEncryptionModes */
int
cpe_get_igd_lan_wlan_basicencryption(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

    DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    if (wsm.mode != WLAN_BASIC) {
        *value = "None";
        return FAULT_CODE_OK;
    }

    switch (wsm.encrypt) {
        case WLAN_NO_ENCRYPTION:
            *value = "None";
            break;
        case WLAN_WEP:
            *value = "WEPEncryption";
        default:
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

int
cpe_set_igd_lan_wlan_basicencryption(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

    DM_TRACE_SET();
    if (!strcmp(value, "None")) {
        wsm.encrypt = WLAN_NO_ENCRYPTION;
    } else if (!strcmp(value, "WEPEncryption")) {
        wsm.encrypt = WLAN_WEP;
    } else {
        cwmp_log_error("%s: invalid value: '%s'", __func__, value);
        return FAULT_CODE_9007;
    }
    nvram_wlan_save(index, &wsm);
    return FAULT_CODE_OK;
}

/* WPAAuthenticationMode */

int cpe_get_igd_lan_wlan_wpaauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

	DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    if (wsm.mode != WLAN_WPA) {
        *value = "PSKAuthentication";
        return FAULT_CODE_OK;
    }

    switch (wsm.authMode) {
        case WLAN_PSK:
            *value = "PSKAuthentication";
            break;
        case WLAN_EAP:
            *value = "EAPAuthentication";
            break;
        default:
            return FAULT_CODE_9002;
    }
    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_wpaauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};
    /* only WPA1 */

	DM_TRACE_SET();
    if (!strcmp(value, "PSKAuthentication")) {
        wsm.authMode = WLAN_PSK;
    } else if (!strcmp(value, "EAPAuthentication")) {
        wsm.authMode = WLAN_EAP;
    } else {
        cwmp_log_error("%s: unknown value: %s", __func__, value);
        return FAULT_CODE_9007;
    }

    nvram_wlan_save(index, &wsm);

    return FAULT_CODE_OK;
}

/* WPAEncryptionModes */
int
cpe_set_igd_lan_wlan_wpaencryption(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

    DM_TRACE_SET();

    if (!strcmp(value, "TKIPEncryption")) {
        wsm.encrypt = WLAN_TKIP;
    } else if (!strcmp(value, "AESEncryption")) {
        wsm.encrypt = WLAN_AES;
    } else if (!strcmp(value, "TKIPandAESEncryption")) {
        wsm.encrypt = WLAN_TKIPAES;
    } else {
        cwmp_log_trace(
                "%s: invalid value '%s', supports only: "
                "TKIPEncryption, AESEncryption, TKIPandAESEncryption",
                __func__, value);
        return FAULT_CODE_9007;
    }
    nvram_wlan_save(index, &wsm);

    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_wpaencryption(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

    DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    if (!(wsm.mode & WLAN_WPA)) {
        /* default value */
        *value = "AESEncryption";
        return FAULT_CODE_OK;
    }

    switch (wsm.encrypt) {
        case WLAN_TKIP:
            *value = "TKIPEncryption";
            break;
        case WLAN_AES:
            *value = "AESEncryption";
            break;
        case WLAN_TKIPAES:
            *value = "TKIPandAESEncryption";
            break;
        default:
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

/* IEEE11iAuthenticationMode */
int cpe_get_igd_lan_wlan_ieeeauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};
    /* WPA2 only */
	DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    if (!(wsm.mode & WLAN_11i)) {
        *value = "PSKAuthentication";
        return FAULT_CODE_OK;
    }

    switch (wsm.authMode) {
        case WLAN_PSK:
            *value = "PSKAuthentication";
            break;
        case WLAN_EAP:
            *value = "EAPAuthentication";
            break;
        default:
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_ieeeauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};
    /* WPA2 */
	DM_TRACE_SET();
    if (!strcmp(value, "PSKAuthentication")) {
        wsm.authMode = WLAN_PSK;
    } else if (!strcmp(value, "EAPAuthentication")) {
        /* Radius auth */
        wsm.authMode = WLAN_EAP;
    } else {
        cwmp_log_error("%s: unknown value: %s", __func__, value);
        return FAULT_CODE_9007;
    }
    nvram_wlan_save(index, &wsm);

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_beacontype(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

	DM_TRACE_GET();
    if (!nvram_wlan_load(index, &wsm)) {
        return FAULT_CODE_9002;
    }

    switch (wsm.mode) {
        case WLAN_WPA:
            *value = "WPA";
            break;
        case WLAN_11i:
            *value = "11i";
            break;
        case WLAN_BASIC:
            *value = "Basic";
            break;
        case WLAN_WPAand11i:
            *value = "WPAand11i";
            break;
    }

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_beacontype(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    const unsigned index = 0u;
    struct wlan_security_mode wsm = {};

	DM_TRACE_SET();

    if (!strcmp(value, "WPAand11i")) {
        /* WPA1WPA2 */
        wsm.mode = WLAN_WPAand11i;
    } else if (!strcmp(value, "11i")) {
        /* WPA2* */
        wsm.mode = WLAN_11i;
    } else if (!strcmp(value, "WPA")) {
        /* WPA* */
        wsm.mode = WLAN_WPA;
    } else if (!strcmp(value, "Basic")) {
        /* OPEN */
        wsm.mode = WLAN_BASIC;
    } else if(!strcmp(value, "None")) {
        /* disable station */
        /* TODO: ... */
        cwmp_log_info("%s: (index: %u) disabling WLAN not supported in this case",
                __func__, index);
        wsm.mode = WLAN_BASIC;
    } else {
        cwmp_log_error("%s: (index: %u) unknown value: '%s'",
                __func__, index, value);
    }
    nvram_wlan_save(index, &wsm);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_possiblechannels(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int v = 0;

    DM_TRACE_GET();
    v = cwmp_nvram_get_int("CountryRegion", -1);

    switch (v) {
        case 0:
            *value = "1-11";
            break;
        case 1:
            *value = "1-13";
            break;
        case 2:
            *value = "10-11";
            break;
        case 3:
            *value = "10-13";
            break;
        case 4:
            *value = "14";
            break;
        case 5:
            *value = "1-14";
            break;
        case 6:
            *value = "3-9";
            break;
        case 7:
            *value = "5-13";
            break;
        default:
            cwmp_log_error("%s: error get CountryRegion nvram value", __func__);
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_status(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *v = NULL;
    DM_TRACE_GET();
    v = cwmp_nvram_get("RadioOn");
    if (*v == '0') {
        *value = "Disabled";
    } else if (*v == '1') {
        *value = "Up";
    } else {
        *value = "Error";
        cwmp_log_error("%s: nvram RadioOn invalid value: '%s'", __func__, v);
    }
    return FAULT_CODE_OK;
}

int
cpe_set_igd_lan_wlan_enabled(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (*value == '0') {
        cwmp_nvram_set("RadioOn", "0");
    } else if (*value == '1') {
        cwmp_nvram_set("RadioOn", "1");
    } else {
        cwmp_log_error("%s: invalid value: '%s'", __func__, value);
        return FAULT_CODE_9007;
    }
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_enabled(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *v = NULL;
    DM_TRACE_GET();
    v = cwmp_nvram_get("RadioOn");
    if (*v == '0') {
        *value = "0";
    } else if (*v == '1') {
        *value = "1";
    } else {
        *value = "0";
        cwmp_log_error("%s: nvram RadioOn invalid value: '%s'", __func__, v);
    }
    return FAULT_CODE_OK;
}



static struct wlan_assoc
{
    char mac[18];
    char addr[40];
    bool authenticated;
} *wlan_assoc;

static unsigned wlan_assoc_count;

static void
igd_lan_wlan_arp(const char *n, struct wlan_assoc *wa)
{
    char arp_addr[40];
    char arp_mac[18];
    FILE *f = fopen("/proc/net/arp", "r");
    int r = EOF;

    if (!f) {
        cwmp_log_error(
                "%s: fopen(\"/proc/net/arp\", \"r\") failure: %s",
                n, strerror(errno));
        return;
    }

	/* skip header */
	fscanf(f, "IP address HW type Flags HW address Mask Device");
	/* process */
	while ((r = fscanf(f, "%s %*x %*x %s %*s %*s",
				arp_addr, arp_mac)) != EOF) {
		/* skip invalid matching */
		if (r != 2)
			continue;
        if (!strcmp(wa->mac, arp_mac)) {
            memcpy(wa->addr, arp_addr, sizeof(wa->addr));
            break;
        }
    }
    fclose(f);
}

int
cpe_refresh_igd_lan_wlan_associated(cwmp_t * cwmp, parameter_node_t * param_node, callback_register_func_t callback_reg)
{
	RT_802_11_MAC_TABLE table24 = {};
	RT_802_11_MAC_ENTRY *pe = NULL;
    int row_no = 0;
    parameter_node_t *pn = NULL;

    DM_TRACE_REFRESH();
    /* delete */
    cwmp_model_delete_object_child(cwmp, param_node);
    if (wlan_assoc) {
        free(wlan_assoc);
        wlan_assoc = NULL;
        wlan_assoc_count = 0u;
    }

    /* populate 2.4GHz */
	getWlanStationTable(&table24, 1);

    wlan_assoc = calloc(table24.Num, sizeof(*wlan_assoc));
    if (!wlan_assoc) {
        cwmp_log_error("%s: calloc(%d) failed: %s",
                __func__, table24.Num * sizeof(*wlan_assoc), strerror(errno));
        return FAULT_CODE_9002;
    }
    wlan_assoc_count = table24.Num;

    for (row_no = 0; row_no < table24.Num; row_no++) {
        pe = &(table24.Entry[row_no]);
        snprintf(wlan_assoc[row_no].mac,
                sizeof(wlan_assoc[row_no].mac),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                pe->Addr[0], pe->Addr[1], pe->Addr[2],
                pe->Addr[3], pe->Addr[4], pe->Addr[5]);
        /* FIXME: too simple */
        igd_lan_wlan_arp(__func__, &wlan_assoc[row_no]);
		cwmp_model_copy_parameter(param_node, &pn, row_no + 1);
    }
    return FAULT_CODE_OK;
}

static long
igd_lan_wlan_no_from_path(cwmp_t *cwmp, const char *name)
{
	parameter_node_t *pn = NULL;
	long no = 0;

	pn = cwmp_get_parameter_path_node(cwmp->root, name);
	if (!pn || !(pn = pn->parent)) {
		cwmp_log_error("%s: can't get rule's number", name);
		return -1;
	}

	no = strtol(pn->name, NULL, 10);

	if (!no) {
		cwmp_log_error("%s: node name '%s' not a valid number", name, pn->name);
		return -1;
	}

	if ((unsigned long)no > wlan_assoc_count) {
		cwmp_log_error("%s: invalid rule number: %lu", name, no);
		return -1;
	}

	return (no - 1);
}


int
cpe_get_igd_lan_wlan_assoc_mac(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int no = -1;
    DM_TRACE_GET();
    no = igd_lan_wlan_no_from_path(cwmp, name);
    if (no == -1) {
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, wlan_assoc[no].mac);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_assoc_addr(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int no = -1;
    DM_TRACE_GET();
    no = igd_lan_wlan_no_from_path(cwmp, name);
    if (no == -1) {
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, wlan_assoc[no].addr);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_assoc_state(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();
    *value = "1";
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_associated_count(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char buf[42] = {};
    DM_TRACE_GET();
    snprintf(buf, sizeof(buf), "%u", wlan_assoc_count);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_set_igd_lan_wlan_wepkey(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
    char tkey[42] = {};
    char key[42] = {};
    char *end = NULL;

    DM_TRACE_SET();
    snprintf(tkey, sizeof(tkey), "Key%sType", args);
    snprintf(key, sizeof(key), "Key%sStr1", args);

    if (length != 10 || length != 26) {
        cwmp_log_trace("%s: invalid value length: %d, must be equal 10 or 26",
                __func__, length);
        return FAULT_CODE_9007;
    }

    strtoul(value, &end, 16);
    if (end && *end) {
        cwmp_log_error("%s: invalid hex: '%s' at symbol number %"PRIuPTR,
            __func__, value, end - value);
        return FAULT_CODE_9007;
    }

    cwmp_nvram_set(tkey, "0");
    cwmp_nvram_set(key, value);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_wepkey(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char tkey[42] = {};
    char key[42] = {};
    char *val = NULL;
    char hex[27];

    DM_TRACE_GET();
    snprintf(tkey, sizeof(tkey), "Key%sType", args);
    snprintf(key, sizeof(key), "Key%sStr1", args);

    if (cwmp_nvram_get_int(tkey, 0) == 0) {
        /* hex value */
        *value = cwmp_nvram_pool_get(pool, key);
    } else {
        /* ASCII value */
        val = cwmp_nvram_get(key);
        if (!*val) {
            return FAULT_CODE_OK;
        }
        cwmp_string_to_hex(val, hex, sizeof(hex));
        *value = pool_pstrdup(pool, hex);
    }
    return FAULT_CODE_OK;
}

static bool
get_igd_lan_wlan_txrx(struct nic_counts *result)
{
    int count = 0;
    int i = 0;
    struct nic_counts *nc = NULL;
    nc = nicscounts(&count);
    for (i = 0; i < count; i++) {
        if (!strcmp(nc[i].ifname, "ra0")) {
            memcpy(result, &nc[i], sizeof(*result));
            goto success;
        }
    }

    if (nc)
        free(nc);
    return false;
success:
    free(nc);
    return true;
}

int
cpe_get_igd_lan_wlan_tx_bytes(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.tx_bytes);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_rx_bytes(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.rx_bytes);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_tx_packets(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.tx_packets);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_rx_packets(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.rx_packets);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_stats(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    parameter_node_t *pn = NULL;
    struct nic_counts nc = {};
    char buf[42] = "0";

    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }

    pn  = cwmp_get_parameter_path_node(cwmp->root, name);

    if (!strcmp("ErrorsSent", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.tx_errs);
    } else if (!strcmp("ErrorsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_errs);
    } else if (!strcmp("UnicastPacketsSent", pn->name)) {
    } else if (!strcmp("UnicastPacketsReceived", pn->name)) {
    } else if (!strcmp("DiscardPacketsSent", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.tx_drops);
    } else if (!strcmp("DiscardPacketsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_drops);
    } else if (!strcmp("MulticastPacketsSent", pn->name)) {
    } else if (!strcmp("MulticastPacketsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_multi);
    } else if (!strcmp("BroadcastPacketsSent", pn->name)) {
    } else if (!strcmp("BroadcastPacketsReceived", pn->name)) {
    } else if (!strcmp("UnknownProtoPacketsReceived", pn->name)) {
    } else {
        cwmp_log_error("%s: unknown node name: %s", __func__, pn->name);
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, buf);

    return FAULT_CODE_OK;
}
int
cpe_set_igd_lan_wlan_ssidadv(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    char *val = NULL;
    pool_t *pool = NULL;

    DM_TRACE_SET();
    pool = pool_create(POOL_DEFAULT_SIZE);
    if (!pool)
        return FAULT_CODE_9002;

    val = cwmp_nvram_pool_get(pool, "HideSSID");
    if (!val) {
        pool_destroy(pool);
        return FAULT_CODE_9002;
    }

    if (*value == '0') {
        *val = '1';
    } else {
        *val = '0';
    }
    cwmp_nvram_set("HideSSID", val);
    pool_destroy(pool);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_ssidadv(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *val = NULL;
    DM_TRACE_GET();

    val = cwmp_nvram_get("HideSSID");
    if (*val == '0') {
        *value = "1";
    } else {
        *value = "0";
    }
    return FAULT_CODE_OK;
}

