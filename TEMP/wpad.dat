var FindProxyForURL = function(init, profiles) {
    return function(url, host) {
        "use strict";
        var result = init, scheme = url.substr(0, url.indexOf(":"));
        do {
            if (!profiles[result]) return result;
            result = profiles[result];
            if (typeof result === "function") result = result(url, host, scheme);
        } while (typeof result !== "string" || result.charCodeAt(0) === 43);
        return result;
    };
}("+0 squid 3128", {
    "+0 squid 3128": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host) || host[host.length - 1] >= 0 && isInNet(host, "192.168.0.0", "255.255.0.0") || host.indexOf(":") >= 0 && (typeof isInNetEx === "function" ? isInNetEx(host, "fe80::/10") : isInNet(host, "fe80::", "ffc0::"))) return "DIRECT";
        return "PROXY 192.168.1.111:3128";
    }
});