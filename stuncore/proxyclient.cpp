/*
   Copyright 2011 John Selbie

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "commonincludes.hpp"
#include "proxyclient.h"
#include "socketaddress.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <map>
#include <string>

using json = nlohmann::json;

// Initialize the static map
std::map<std::string, CProxyClient::CachedIP> CProxyClient::_ip_cache;
std::map<std::string, CProxyClient::CachedProxy> CProxyClient::_proxy_cache;

CProxyClient::CProxyClient() : _proxyPort(0) {
}

CProxyClient::~CProxyClient() {
}

HRESULT CProxyClient::ParseProxyUrl(const std::string& url) {
    HRESULT hr = S_OK;
    std::string scheme, host, port, user, pass;
    
    Logging::LogMsg(LL_ALWAYS, "Parsing proxy URL: %s", url.c_str());
    
    // Parse scheme://username:password@host:port
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        Logging::LogMsg(LL_ALWAYS, "Invalid proxy URL format - missing scheme://");
        return E_INVALIDARG;
    }
    
    scheme = url.substr(0, schemeEnd);
    if (scheme != "socks5" && scheme != "http" && scheme != "https") {
        Logging::LogMsg(LL_ALWAYS, "Unsupported proxy scheme: %s", scheme.c_str());
        return E_INVALIDARG;
    }
    
    _proxyScheme = scheme;
    Logging::LogMsg(LL_ALWAYS, "Using proxy scheme: %s", _proxyScheme.c_str());
    
    std::string rest = url.substr(schemeEnd + 3);
    size_t atPos = rest.find('@');
    if (atPos != std::string::npos) {
        std::string auth = rest.substr(0, atPos);
        size_t colonPos = auth.find(':');
        if (colonPos != std::string::npos) {
            _proxyUser = auth.substr(0, colonPos);
            _proxyPass = auth.substr(colonPos + 1);
            Logging::LogMsg(LL_ALWAYS, "Proxy authentication: username=%s", _proxyUser.c_str());
        }
        rest = rest.substr(atPos + 1);
    }
    
    size_t portPos = rest.find(':');
    if (portPos != std::string::npos) {
        _proxyHost = rest.substr(0, portPos);
        _proxyPort = static_cast<uint16_t>(std::stoi(rest.substr(portPos + 1)));
    } else {
        _proxyHost = rest;
        // Set default ports based on scheme
        if (scheme == "socks5") {
            _proxyPort = 1080;
        } else if (scheme == "http") {
            _proxyPort = 80;
        } else if (scheme == "https") {
            _proxyPort = 443;
        }
    }
    
    Logging::LogMsg(LL_ALWAYS, "Proxy host: %s, port: %d", _proxyHost.c_str(), _proxyPort);
    
    return hr;
}

HRESULT CProxyClient::GetPublicIP(const std::string& clientIP, std::string& publicIP) {
    Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Getting public IP for client %s", clientIP.c_str());

    HRESULT hr = S_OK;
    CURLcode res = CURLE_OK;
    long http_code = 0;
    double total_time = 0;
    WriteContext ctx;
    std::string routing_response;
    std::string proxy_response;
    bool use_cached_proxy = false;

    // Extract IP address without port
    std::string cleanIP = clientIP;
    size_t colonPos = cleanIP.find(':');
    if (colonPos != std::string::npos) {
        cleanIP = cleanIP.substr(0, colonPos);
        Logging::LogMsg(LL_ALWAYS, "Extracted IP address without port: %s", cleanIP.c_str());
    }

    // Check proxy cache first
    auto now = std::chrono::steady_clock::now();
    auto proxy_it = _proxy_cache.find(cleanIP);
    if (proxy_it != _proxy_cache.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - proxy_it->second.timestamp);
        Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache entry found for client IP %s. Timestamp: %llds ago", cleanIP.c_str(), duration.count());
        if (duration.count() < 5) {
            routing_response = proxy_it->second.proxy_url;
            Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache hit for client IP %s. Using cached proxy URL: %s", cleanIP.c_str(), routing_response.c_str());
            use_cached_proxy = true;
        } else {
            Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache expired for client IP %s. Duration: %llds. Fetching new proxy URL.", cleanIP.c_str(), duration.count());
        }
    } else {
        Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache miss for client IP %s. Fetching new proxy URL.", cleanIP.c_str());
    }

    if (!use_cached_proxy) {
        CURLM* multi_handle = NULL;
        CURL* routing_curl = NULL;
        CURL* proxy_curl = NULL;
        char errbuf[CURL_ERROR_SIZE];
        CURLMcode mres;
        struct curl_slist* headers = NULL;
        FILE* routing_temp_file = NULL;
        FILE* proxy_temp_file = NULL;
        char routing_temp_filename[] = "/tmp/curl_routing_XXXXXX";
        char proxy_temp_filename[] = "/tmp/curl_proxy_XXXXXX";
        int still_running = 0;

        // Create temporary files
        int routing_fd = mkstemp(routing_temp_filename);
        int proxy_fd = mkstemp(proxy_temp_filename);
        if (routing_fd == -1 || proxy_fd == -1) {
            Logging::LogMsg(LL_ALWAYS, "Failed to create temporary files");
            if (routing_fd != -1) close(routing_fd);
            if (proxy_fd != -1) close(proxy_fd);
            return E_FAIL;
        }

        routing_temp_file = fdopen(routing_fd, "w+");
        proxy_temp_file = fdopen(proxy_fd, "w+");
        if (!routing_temp_file || !proxy_temp_file) {
            Logging::LogMsg(LL_ALWAYS, "Failed to open temporary files");
            if (routing_temp_file) fclose(routing_temp_file);
            if (proxy_temp_file) fclose(proxy_temp_file);
            if (routing_fd != -1) close(routing_fd);
            if (proxy_fd != -1) close(proxy_fd);
            unlink(routing_temp_filename);
            unlink(proxy_temp_filename);
            return E_FAIL;
        }

        // Initialize multi handle
        multi_handle = curl_multi_init();
        if (!multi_handle) {
            Logging::LogMsg(LL_ALWAYS, "Failed to initialize CURL multi handle");
            fclose(routing_temp_file);
            fclose(proxy_temp_file);
            unlink(routing_temp_filename);
            unlink(proxy_temp_filename);
            return E_FAIL;
        }

        // Initialize CURL handles
        routing_curl = curl_easy_init();
        if (!routing_curl) {
            Logging::LogMsg(LL_ALWAYS, "Failed to initialize routing CURL handle");
            curl_multi_cleanup(multi_handle);
            fclose(routing_temp_file);
            fclose(proxy_temp_file);
            unlink(routing_temp_filename);
            unlink(proxy_temp_filename);
            return E_FAIL;
        }

        // Set up routing engine request
        std::string routingUrl = "http://192.168.137.135:8080/api/routing-engine/current-mappings?ip=" + cleanIP;
        Logging::LogMsg(LL_ALWAYS, "Requesting proxy URL from routing engine: %s", routingUrl.c_str());

        errbuf[0] = '\0';
        curl_easy_setopt(routing_curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(routing_curl, CURLOPT_URL, routingUrl.c_str());
        curl_easy_setopt(routing_curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(routing_curl, CURLOPT_WRITEDATA, routing_temp_file);
        curl_easy_setopt(routing_curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(routing_curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(routing_curl, CURLOPT_BUFFERSIZE, 1024L);
        curl_easy_setopt(routing_curl, CURLOPT_NOSIGNAL, 1L);

        // Set headers
        headers = curl_slist_append(headers, "Accept: application/json");
        if (headers) {
            headers = curl_slist_append(headers, "Content-Type: application/json");
        }
        if (!headers) {
            Logging::LogMsg(LL_ALWAYS, "Failed to set HTTP headers");
            curl_easy_cleanup(routing_curl);
            curl_multi_cleanup(multi_handle);
            curl_slist_free_all(headers);
            fclose(routing_temp_file);
            fclose(proxy_temp_file);
            unlink(routing_temp_filename);
            unlink(proxy_temp_filename);
            return E_FAIL;
        }

        curl_easy_setopt(routing_curl, CURLOPT_HTTPHEADER, headers);

        // Add routing handle to multi
        mres = curl_multi_add_handle(multi_handle, routing_curl);
        if (mres != CURLM_OK) {
            Logging::LogMsg(LL_ALWAYS, "Failed to add routing handle to multi: %s", curl_multi_strerror(mres));
            curl_easy_cleanup(routing_curl);
            curl_multi_cleanup(multi_handle);
            curl_slist_free_all(headers);
            fclose(routing_temp_file);
            fclose(proxy_temp_file);
            unlink(routing_temp_filename);
            unlink(proxy_temp_filename);
            return E_FAIL;
        }

        // Process routing request
        do {
            mres = curl_multi_perform(multi_handle, &still_running);
            if (mres != CURLM_OK) {
                Logging::LogMsg(LL_ALWAYS, "Failed to perform routing request: %s", curl_multi_strerror(mres));
                break;
            }

            // Wait for activity
            int numfds;
            mres = curl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);
            if (mres != CURLM_OK) {
                Logging::LogMsg(LL_ALWAYS, "Failed to wait for routing response: %s", curl_multi_strerror(mres));
                break;
            }

            // Check for completed transfers
            CURLMsg* msg;
            int msgs_left;
            while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
                if (msg->msg == CURLMSG_DONE && msg->easy_handle == routing_curl) {
                    // Handle routing engine response
                    curl_easy_getinfo(routing_curl, CURLINFO_RESPONSE_CODE, &http_code);
                    curl_easy_getinfo(routing_curl, CURLINFO_TOTAL_TIME, &total_time);
                    Logging::LogMsg(LL_ALWAYS, "Routing engine response code: %ld, Total Time: %.2f seconds",
                                  http_code, total_time);

                    if (msg->data.result != CURLE_OK) {
                        Logging::LogMsg(LL_ALWAYS, "Routing engine request failed: %s",
                                      curl_easy_strerror(msg->data.result));
                        hr = E_FAIL;
                        break;
                    }

                    // Read routing response
                    fseek(routing_temp_file, 0, SEEK_END);
                    long file_size = ftell(routing_temp_file);
                    fseek(routing_temp_file, 0, SEEK_SET);

                    if (file_size <= 0) {
                        Logging::LogMsg(LL_ALWAYS, "Empty response from routing engine");
                        hr = E_FAIL;
                        break;
                    }

                    routing_response.resize(file_size);
                    size_t read_size = fread(&routing_response[0], 1, file_size, routing_temp_file);
                    if (read_size != static_cast<size_t>(file_size)) {
                        Logging::LogMsg(LL_ALWAYS, "Failed to read routing response");
                        hr = E_FAIL;
                        break;
                    }

                    Logging::LogMsg(LL_ALWAYS, "Received proxy URL from routing engine: %s", routing_response.c_str());

                    // Cache the proxy URL
                    auto now_cache = std::chrono::steady_clock::now();
                    _proxy_cache[cleanIP] = {routing_response, now_cache};
                    Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Successfully cached proxy URL %s for client IP %s", routing_response.c_str(), cleanIP.c_str());

                    curl_multi_remove_handle(multi_handle, routing_curl);
                    curl_easy_cleanup(routing_curl);
                    routing_curl = NULL;
                }
            }
        } while (still_running && routing_curl);

        // Cleanup routing resources
        if (multi_handle) {
            curl_multi_cleanup(multi_handle);
        }
        if (headers) {
            curl_slist_free_all(headers);
        }
        if (routing_temp_file) {
            fclose(routing_temp_file);
        }
        if (proxy_temp_file) {
            fclose(proxy_temp_file);
        }
        unlink(routing_temp_filename);
        unlink(proxy_temp_filename);

        if (FAILED(hr)) {
            return hr;
        }
    }

    // Check IP cache
    auto ip_it = _ip_cache.find(routing_response);
    if (ip_it != _ip_cache.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - ip_it->second.timestamp);
        Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache entry found for proxy URL %s. Timestamp: %llds ago", routing_response.c_str(), duration.count());
        if (duration.count() < 5) {
            publicIP = ip_it->second.ip_address;
            Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache hit for proxy URL %s. Returning cached IP: %s", routing_response.c_str(), publicIP.c_str());
            return S_OK;
        } else {
            Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache expired for proxy URL %s. Duration: %llds. Fetching new IP.", routing_response.c_str(), duration.count());
        }
    } else {
        Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Cache miss for proxy URL %s. Fetching new IP.", routing_response.c_str());
    }

    // Parse proxy URL and make proxy request
    hr = ParseProxyUrl(routing_response);
    if (FAILED(hr)) {
        Logging::LogMsg(LL_ALWAYS, "Failed to parse proxy URL");
        return hr;
    }

    // Initialize new CURL resources for proxy request
    CURLM* multi_handle = curl_multi_init();
    CURL* proxy_curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];
    CURLMcode mres;
    struct curl_slist* headers = NULL;
    FILE* proxy_temp_file = NULL;
    char proxy_temp_filename[] = "/tmp/curl_proxy_XXXXXX";
    int still_running = 0;

    if (!multi_handle || !proxy_curl) {
        Logging::LogMsg(LL_ALWAYS, "Failed to initialize CURL handles for proxy request");
        if (multi_handle) curl_multi_cleanup(multi_handle);
        if (proxy_curl) curl_easy_cleanup(proxy_curl);
        return E_FAIL;
    }

    // Create temporary file for proxy response
    int proxy_fd = mkstemp(proxy_temp_filename);
    if (proxy_fd == -1) {
        Logging::LogMsg(LL_ALWAYS, "Failed to create temporary file for proxy response");
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(proxy_curl);
        return E_FAIL;
    }

    proxy_temp_file = fdopen(proxy_fd, "w+");
    if (!proxy_temp_file) {
        Logging::LogMsg(LL_ALWAYS, "Failed to open temporary file for proxy response");
        close(proxy_fd);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(proxy_curl);
        unlink(proxy_temp_filename);
        return E_FAIL;
    }

    // Set up proxy request
    errbuf[0] = '\0';
    curl_easy_setopt(proxy_curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(proxy_curl, CURLOPT_URL, "https://geo.myip.link");
    curl_easy_setopt(proxy_curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(proxy_curl, CURLOPT_WRITEDATA, proxy_temp_file);
    curl_easy_setopt(proxy_curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(proxy_curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(proxy_curl, CURLOPT_BUFFERSIZE, 1024L);
    curl_easy_setopt(proxy_curl, CURLOPT_NOSIGNAL, 1L);

    // Set headers
    headers = curl_slist_append(headers, "Accept: application/json");
    if (headers) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }
    if (!headers) {
        Logging::LogMsg(LL_ALWAYS, "Failed to set HTTP headers for proxy request");
        fclose(proxy_temp_file);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(proxy_curl);
        unlink(proxy_temp_filename);
        return E_FAIL;
    }

    curl_easy_setopt(proxy_curl, CURLOPT_HTTPHEADER, headers);

    // Set proxy options
    curl_easy_setopt(proxy_curl, CURLOPT_PROXY, _proxyHost.c_str());
    curl_easy_setopt(proxy_curl, CURLOPT_PROXYPORT, _proxyPort);

    if (_proxyScheme == "socks5") {
        curl_easy_setopt(proxy_curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        Logging::LogMsg(LL_ALWAYS, "Using SOCKS5 proxy");
    } else if (_proxyScheme == "http") {
        curl_easy_setopt(proxy_curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        Logging::LogMsg(LL_ALWAYS, "Using HTTP proxy");
    } else if (_proxyScheme == "https") {
        curl_easy_setopt(proxy_curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTPS);
        Logging::LogMsg(LL_ALWAYS, "Using HTTPS proxy");
    }

    if (!_proxyUser.empty()) {
        std::string auth = _proxyUser + ":" + _proxyPass;
        curl_easy_setopt(proxy_curl, CURLOPT_PROXYUSERPWD, auth.c_str());
        Logging::LogMsg(LL_ALWAYS, "Using proxy authentication");
    }

    // Add proxy handle to multi
    mres = curl_multi_add_handle(multi_handle, proxy_curl);
    if (mres != CURLM_OK) {
        Logging::LogMsg(LL_ALWAYS, "Failed to add proxy handle to multi: %s", curl_multi_strerror(mres));
        fclose(proxy_temp_file);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(proxy_curl);
        curl_slist_free_all(headers);
        unlink(proxy_temp_filename);
        return E_FAIL;
    }

    // Process proxy request
    do {
        mres = curl_multi_perform(multi_handle, &still_running);
        if (mres != CURLM_OK) {
            Logging::LogMsg(LL_ALWAYS, "Failed to perform proxy request: %s", curl_multi_strerror(mres));
            break;
        }

        int numfds;
        mres = curl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);
        if (mres != CURLM_OK) {
            Logging::LogMsg(LL_ALWAYS, "Failed to wait for proxy response: %s", curl_multi_strerror(mres));
            break;
        }

        CURLMsg* msg;
        int msgs_left;
        while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE && msg->easy_handle == proxy_curl) {
                curl_easy_getinfo(proxy_curl, CURLINFO_RESPONSE_CODE, &http_code);
                curl_easy_getinfo(proxy_curl, CURLINFO_TOTAL_TIME, &total_time);
                Logging::LogMsg(LL_ALWAYS, "Proxy response code: %ld, Total Time: %.2f seconds",
                              http_code, total_time);

                if (msg->data.result != CURLE_OK) {
                    Logging::LogMsg(LL_ALWAYS, "Proxy request failed: %s",
                                  curl_easy_strerror(msg->data.result));
                    hr = E_FAIL;
                    break;
                }

                fseek(proxy_temp_file, 0, SEEK_END);
                long file_size = ftell(proxy_temp_file);
                fseek(proxy_temp_file, 0, SEEK_SET);

                if (file_size <= 0) {
                    Logging::LogMsg(LL_ALWAYS, "Empty response from proxy");
                    hr = E_FAIL;
                    break;
                }

                proxy_response.resize(file_size);
                size_t read_size = fread(&proxy_response[0], 1, file_size, proxy_temp_file);
                if (read_size != static_cast<size_t>(file_size)) {
                    Logging::LogMsg(LL_ALWAYS, "Failed to read proxy response");
                    hr = E_FAIL;
                    break;
                }

                Logging::LogMsg(LL_ALWAYS, "Received response from proxy: %s", proxy_response.c_str());

                try {
                    json j = json::parse(proxy_response);
                    std::string rawIP = j["ip"].get<std::string>();

                    Logging::LogMsg(LL_ALWAYS, "Raw IP from JSON: %s", rawIP.c_str());

                    publicIP = rawIP;
                    Logging::LogMsg(LL_ALWAYS, "Successfully got public IP: %s", publicIP.c_str());

                    // Cache the IP
                    auto now_update = std::chrono::steady_clock::now();
                    _ip_cache[routing_response] = {publicIP, now_update};
                    Logging::LogMsg(LL_ALWAYS, "CProxyClient::GetPublicIP: Successfully obtained IP %s. Updating cache for proxy URL %s.", publicIP.c_str(), routing_response.c_str());
                } catch (const std::exception& e) {
                    Logging::LogMsg(LL_ALWAYS, "Failed to parse JSON response: %s", e.what());
                    hr = E_FAIL;
                    break;
                }
            }
        }
    } while (still_running && proxy_curl);

    // Cleanup proxy resources
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }
    if (headers) {
        curl_slist_free_all(headers);
    }
    if (proxy_temp_file) {
        fclose(proxy_temp_file);
    }
    unlink(proxy_temp_filename);

    return hr;
}

size_t CProxyClient::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    // ... existing code ...
} 