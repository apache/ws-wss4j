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

package org.apache.ws.axis.security.conversation;

import org.apache.ws.security.conversation.ConversationConstants;

import java.util.Hashtable;
import java.util.Map;

/**
 * Represents parameters given in the wsdd file.
 *
 * @author Dimuthu Leelarathne.(muthulee@yahoo.com)
 */
public class ConvHandlerConstants {

    public static final String SEVER_PROP_FILE = "serverPropFile";
    public static final String REQUESTOR_PROP_FILE = "requestorPropFile";
    public static final String STS_PROP_FILE = "trustServicePropFile";

    public static final String REAP_FREQ = "reapFrequency";
    public static final String SESSION_DURATION = "sessionDuration";

    public static final String KEY_FREQ = "keyFrequency";
    public static final String USE_FIXED_KEYLEN = "useFixedKeyLegnth";

    public static final String KEY_LEGNTH = "keyLegnth";
    public static final String GENERATION = "generation";

    public static final String SEVER_ALIAS = "serverAlias";
    public static final String REQ_ALIAS = "requestorAlias";

    public static final String SIGN_PARTS = "signatureParts";

    public static final String TRUST_ENABLE = "trustEnable";

    public static final String SCT_ESTABLISH_MTD = "sctEstablishmentMtd";

    public static final String VERIFY_TRUST = "verifyTrust";

    public static final String TRUST_ENGINE_PROP = "trustEngineProperties";

    public static final String DK_ACTION = "derivedKeyAction";
    public static final String APPLIES_TO_VAL = "appliesToValue";

    public static final String STS_ADDRESS = "stsAddress";
    public static final String CONV_CALLBACK = "convCBHandler";

    public static Map sctEstablishmentMapper = new Hashtable();
    
    /**
     * Mapps the strings to internally used integers.
     */
    static {
        sctEstablishmentMapper.put("DirectGenerated",
                new Integer(ConversationConstants.DIRECT_GENERATED));
        sctEstablishmentMapper.put("STSGenerated",
                new Integer(ConversationConstants.STS_GENERATED));
    }

}