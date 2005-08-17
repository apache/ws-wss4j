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

package org.apache.ws.sandbox.security.trust2.serialization;

import org.apache.ws.sandbox.security.trust2.RequestSecurityTokenResponse;
import org.apache.ws.sandbox.security.trust2.TrustConstants;
import org.apache.axis.encoding.DeserializationContext;
import org.apache.axis.encoding.DeserializerImpl;
import org.apache.axis.message.SOAPHandler;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;

/**
 * @author ddelvecc
 *         <p/>
 *         For deserializing RequestSecurityTokenResponse objects/elements.
 */
public class RSTResponseDeserializer extends DeserializerImpl {
    public static final QName myTypeQName = TrustConstants.RESPONSE_NAME;

    private RequestSecurityTokenResponse tokenResponse;

    public RSTResponseDeserializer() {
    }

    public SOAPHandler onStartChild(String namespace, String localName, String prefix, Attributes attributes, DeserializationContext context)
            throws SAXException {

        try {
            tokenResponse = new RequestSecurityTokenResponse(context.getCurElement().getAsDOM(), context.getEnvelope().getAsDocument());
            value = tokenResponse;
        } catch (Exception e) {
            throw new SAXException("Exception while processing RequestSecurityTokenResponse startElement: " + e.getMessage());
        }

        return null;
    }
}
