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

package org.apache.ws.security.message;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS Timestamp and inserts it into the SOAP Envelope. 
 * Refer to the WS specification 1.0. chapter 10 / appendix A.2
 * 
 * @author Christof Soehngen (Christof.Soehngen@syracom.de).
 */

public class WSAddTimestamp extends WSBaseMessage {
    private static Log log = LogFactory.getLog(WSAddTimestamp.class.getName());
    
	private Timestamp ts = null;

    /**
     * Constructor.
     */
    public WSAddTimestamp() {
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param actor the name of the actor of the <code>wsse:Security</code> header
     */
    public WSAddTimestamp(String actor) {
        super(actor);
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param actor The name of the actor of the <code>wsse:Security</code> header
     * @param mu    Set <code>mustUnderstand</code> to true or false
     */
    public WSAddTimestamp(String actor, boolean mu) {
        super(actor, mu);
    }

    /**
     * Adds a new <code>Timestamp</code> to a soap envelope.
     * <p/>
     * A complete <code>Timestamp</code> is constructed and added to
     * the <code>wsse:Security</code> header. 
     * 
     * @param doc      The SOAP enevlope as W3C document
     * @param ttl      This is the time difference in seconds between the <code>Created</code> and the <code>Expires</code> in <code>Timestamp</code>
     * @return Document with Timestamp added
     * @throws Exception 
     */
    public Document build(Document doc, int ttl) { 
        log.debug("Begin add timestamp...");
		Element securityHeader = insertSecurityHeader(doc);
        ts = new Timestamp(doc, ttl);
        WSSecurityUtil.prependChildElement(doc, securityHeader, ts.getElement(), true);
        return doc;
    }

}