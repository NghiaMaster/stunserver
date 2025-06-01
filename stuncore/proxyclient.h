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

#ifndef PROXYCLIENT_H
#define PROXYCLIENT_H

#include "commonincludes.hpp"
#include "socketaddress.h"

class CProxyClient {
private:
    std::string _proxyUrl;
    std::string _proxyHost;
    uint16_t _proxyPort;
    std::string _proxyUsername;
    std::string _proxyPassword;

    HRESULT ParseProxyUrl(const std::string& url);
    HRESULT ConnectToProxy();
    HRESULT SendSocks5Request(const std::string& targetHost, uint16_t targetPort);
    HRESULT ReadSocks5Response();
    HRESULT SendHttpRequest(const std::string& url, std::string& response);
    HRESULT ParseJsonResponse(const std::string& json, std::string& ip);

public:
    CProxyClient();
    ~CProxyClient();

    HRESULT GetPublicIP(const std::string& clientIP, std::string& publicIP);
};

#endif // PROXYCLIENT_H 