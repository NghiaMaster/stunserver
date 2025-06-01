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

using json = nlohmann::json;

CProxyClient::CProxyClient() : _proxyPort(0) {
}

CProxyClient::~CProxyClient() {
}

HRESULT CProxyClient::ParseProxyUrl(const std::string& url) {
    HRESULT hr = S_OK;
    std::string scheme, host, port, user, pass;
    
    // Parse socks5://username:password@host:port
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        return E_INVALIDARG;
    }
    
    scheme = url.substr(0, schemeEnd);
    if (scheme != "socks5") {
        return E_INVALIDARG;
    }
    
    std::string rest = url.substr(schemeEnd + 3);
    size_t atPos = rest.find('@');
    if (atPos != std::string::npos) {
        std::string auth = rest.substr(0, atPos);
        size_t colonPos = auth.find(':');
        if (colonPos != std::string::npos) {
            _proxyUsername = auth.substr(0, colonPos);
            _proxyPassword = auth.substr(colonPos + 1);
        }
        rest = rest.substr(atPos + 1);
    }
    
    size_t portPos = rest.find(':');
    if (portPos != std::string::npos) {
        _proxyHost = rest.substr(0, portPos);
        _proxyPort = static_cast<uint16_t>(std::stoi(rest.substr(portPos + 1)));
    } else {
        _proxyHost = rest;
        _proxyPort = 1080; // Default SOCKS5 port
    }
    
    return hr;
}

HRESULT CProxyClient::GetPublicIP(const std::string& clientIP, std::string& publicIP) {
    HRESULT hr = S_OK;
    CURL* curl = NULL;
    std::string response;
    
    // First get the proxy URL from the routing engine
    curl = curl_easy_init();
    if (!curl) {
        return E_FAIL;
    }
    
    std::string routingUrl = "http://192.168.137.135:8080/api/routing-engine/current-mappings?ip=" + clientIP;
    curl_easy_setopt(curl, CURLOPT_URL, routingUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* contents, size_t size, size_t nmemb, std::string* s) -> size_t {
        size_t newLength = size * nmemb;
        try {
            s->append((char*)contents, newLength);
            return newLength;
        } catch(std::bad_alloc& e) {
            return static_cast<size_t>(0);
        }
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        hr = E_FAIL;
        goto cleanup;
    }
    
    // Parse the proxy URL
    hr = ParseProxyUrl(response);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Now use the proxy to get the public IP
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "http://geo.myip.link");
    curl_easy_setopt(curl, CURLOPT_PROXY, _proxyHost.c_str());
    curl_easy_setopt(curl, CURLOPT_PROXYPORT, _proxyPort);
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    
    if (!_proxyUsername.empty()) {
        std::string auth = _proxyUsername + ":" + _proxyPassword;
        curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, auth.c_str());
    }
    
    response.clear();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* contents, size_t size, size_t nmemb, std::string* s) -> size_t {
        size_t newLength = size * nmemb;
        try {
            s->append((char*)contents, newLength);
            return newLength;
        } catch(std::bad_alloc& e) {
            return static_cast<size_t>(0);
        }
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        hr = E_FAIL;
        goto cleanup;
    }
    
    // Parse the JSON response
    try {
        json j = json::parse(response);
        publicIP = j["ip"].get<std::string>();
    } catch (const std::exception& e) {
        hr = E_FAIL;
        goto cleanup;
    }
    
cleanup:
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return hr;
} 