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

package org.apache.ws.sandbox.axis.security.conversation;


import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.sandbox.security.conversation.ConversationConstants;
import org.apache.ws.security.transform.STRTransform;
import org.apache.xml.security.transforms.Transform;

import java.util.Hashtable;
import java.util.Map;

/**
 * Represents parameters given in the wsdd file.
 *
 * @author Dimuthu Leelarathne.(muthulee@yahoo.com)
 */
public class ConvHandlerConstants {

    private static Log log =
        LogFactory.getLog(ConvHandlerConstants.class.getName());
	
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
    public static final String STS_REQUSTOR_TYPE = "stsRequestorType";

    public static final String VERIFY_TRUST = "verifyTrust";

    public static final String TRUST_ENGINE_PROP = "trustEngineProperties";

    public static final String DK_ACTION = "derivedKeyAction";
    public static final String APPLIES_TO_VAL = "appliesToValue";

    public static Map sctEstablishmentMapper = new Hashtable();
    
    public static Map requesterTypeMapper = new Hashtable();
    //TODO::Remove the below line
	public static final String CONV_CALLBACK = "pwcallback";
    
    public static final String SCT_ISSUE_ACTION = "http://schemas.xmlsoap.org/ws/2005/XX/security/trust/RST/SCT";
    
    
    
	
	/**
	 * Which algorithm to be used for encryption as in AES or DES and so on
	 * 
	 * @see WSConstants#TRIPLE_DES
     * @see WSConstants#AES_128
     * @see WSConstants#AES_192
     * @see WSConstants#AES_256
	 */
	public static final String DK_ENC_ALGO = "dkEncryptionAlgorithm";
	
	
    
    /*
     * Constants needed for trust
     */
	public static final String STS_ADDRESS = "stsAddress";
	public static final String SERVICE_EPR = "serviceEPR";
    
    
    public static final String TOKEN_TRUST_VERIFY = "verifyToken";
    
    public static final String DK_CB_HANDLER = "DkcbHandler";
    
    /*
     * Mapps the strings to internally used integers.
     */
    static {
        sctEstablishmentMapper.put("DirectGenerated",
                new Integer(ConversationConstants.DIRECT_GENERATED));
        sctEstablishmentMapper.put("STSGenerated",
                new Integer(ConversationConstants.STS_GENERATED));
		sctEstablishmentMapper.put("STSRequestToken",
						new Integer(ConversationConstants.STSREQUEST_TOKEN));
		sctEstablishmentMapper.put("InteropHandshake",
								new Integer(ConversationConstants.INTEROP_SCENE1));
    }
}