/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.trust2;

import javax.xml.namespace.QName;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * @author ddelvecc
 *         <p/>
 *         WS-Trust constants.
 */
public abstract class TrustConstants {

    private static final String NS_YEAR_PREFIX = "http://schemas.xmlsoap.org/ws/2004/04/";
    public static final String WST_NS = NS_YEAR_PREFIX + "trust";
    public static final String WST_PREFIX = "wst:";

    public static final String REQUEST_TAG = "RequestSecurityToken";
    public static final QName REQUEST_NAME = new QName(WST_NS, REQUEST_TAG, WST_PREFIX);

    public static final String CONTEXT_ATTR = "Context";
    public static final String TOKEN_TYPE = "TokenType";
    public static final String REQUEST_TYPE = "RequestType";
    public static final String BASE = "Base";
    public static final String SUPPORTING = "Supporting";
    public static final String LIFETIME = "Lifetime";
    public static final String LIFETIME_MS = "LifeTime";

    public static final boolean MS_COMPATIBLE_LIFETIMES = true;

    public static final String RESPONSE_TAG = "RequestSecurityTokenResponse";
    public static final QName RESPONSE_NAME = new QName(WST_NS, RESPONSE_TAG, WST_PREFIX);

    public static final String REQUESTED_TOKEN = "RequestedSecurityToken";
    public static final String REQUESTED_PROOF = "RequestedProofToken";

    public static final String WSA_NS = "http://schemas.xmlsoap.org/ws/2004/03/addressing";
    public static final String WSA_PREFIX = "wsa:";
    public static final String ACTION_TAG = "Action";

    private static final String SECURITY_TRUST_PREFIX = NS_YEAR_PREFIX + "security/trust/";

    public static URI REQUEST_ISSUE;
    public static URI REQUEST_RENEW;
    public static URI REQUEST_VALIDATE;

    private static final String ACTION_REQUEST_PREFIX = SECURITY_TRUST_PREFIX + "RST/";

    public static URI ACTION_REQUEST_ISSUE;
    public static URI ACTION_REQUEST_RENEW;
    public static URI ACTION_REQUEST_VALIDATE;

    private static final String ACTION_RESPONSE_PREFIX = SECURITY_TRUST_PREFIX + "RSTR/";

    public static URI ACTION_RESPONSE_ISSUE;
    public static URI ACTION_RESPONSE_RENEW;
    public static URI ACTION_RESPONSE_VALIDATE;

    static {
        try {
            REQUEST_ISSUE = new URI(SECURITY_TRUST_PREFIX + "Issue");
            REQUEST_RENEW = new URI(SECURITY_TRUST_PREFIX + "Renew");
            REQUEST_VALIDATE = new URI(SECURITY_TRUST_PREFIX + "Validate");

            ACTION_REQUEST_ISSUE = new URI(ACTION_REQUEST_PREFIX + "Issue");
            ACTION_REQUEST_RENEW = new URI(ACTION_REQUEST_PREFIX + "Renew");
            ACTION_REQUEST_VALIDATE = new URI(ACTION_REQUEST_PREFIX + "Validate");

            ACTION_RESPONSE_ISSUE = new URI(ACTION_RESPONSE_PREFIX + "Issue");
            ACTION_RESPONSE_RENEW = new URI(ACTION_RESPONSE_PREFIX + "Renew");
            ACTION_RESPONSE_VALIDATE = new URI(ACTION_RESPONSE_PREFIX + "Validate");
        } catch (URISyntaxException e) {
        }
    }

    public static URI getActionRequest(URI requestType) {
        if (REQUEST_ISSUE.equals(requestType))
            return ACTION_REQUEST_ISSUE;
        if (REQUEST_ISSUE.equals(requestType))
            return ACTION_REQUEST_RENEW;
        if (REQUEST_ISSUE.equals(requestType))
            return ACTION_REQUEST_VALIDATE;
        return requestType;
    }
}
