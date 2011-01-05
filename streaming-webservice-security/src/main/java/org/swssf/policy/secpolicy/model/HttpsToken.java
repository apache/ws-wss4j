/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.swssf.policy.secpolicy.model;

import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;
import org.apache.neethi.PolicyComponent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Collection;
import java.util.Map;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */

/**
 * class lent from apache rampart
 */
public class HttpsToken extends Token {

    public HttpsToken(SPConstants spConstants) {
        setVersion(spConstants);
    }

    private boolean requireClientCertificate = false;
    private boolean httpBasicAuthentication = false;
    private boolean httpDigestAuthentication = false;

    public boolean isRequireClientCertificate() {
        return requireClientCertificate;
    }

    public void setRequireClientCertificate(boolean requireClientCertificate) {
        this.requireClientCertificate = requireClientCertificate;
    }

    /**
     * @return the httpBasicAuthentication
     */
    public boolean isHttpBasicAuthentication() {
        return httpBasicAuthentication;
    }

    /**
     * @param httpBasicAuthentication the httpBasicAuthentication to set
     */
    public void setHttpBasicAuthentication(boolean httpBasicAuthentication) {
        this.httpBasicAuthentication = httpBasicAuthentication;
    }

    /**
     * @return the httpDigestAuthentication
     */
    public boolean isHttpDigestAuthentication() {
        return httpDigestAuthentication;
    }

    /**
     * @param httpDigestAuthentication the httpDigestAuthentication to set
     */
    public void setHttpDigestAuthentication(boolean httpDigestAuthentication) {
        this.httpDigestAuthentication = httpDigestAuthentication;
    }

    public QName getName() {
        return spConstants.getHttpsToken();
    }

    public PolicyComponent normalize() {
        throw new UnsupportedOperationException();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {

        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);
        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:HttpsToken
        writer.writeStartElement(prefix, localname, namespaceURI);


        if (spConstants.getVersion() == SPConstants.Version.SP_V12) {

            if (isRequireClientCertificate() ||
                    isHttpBasicAuthentication() ||
                    isHttpDigestAuthentication()) {
                // <wsp:Policy>
                writer.writeStartElement(SPConstants.POLICY.getPrefix(), SPConstants.POLICY.getLocalPart(), SPConstants.POLICY.getNamespaceURI());

                /*
                *  The ws policy 1.2 specification states that only one of those should be present, although
                * a web server (say tomcat) could be normally configured to require both a client certificate and
                * a http user/pwd authentication. Nevertheless stick to the specification.
                */
                if (isHttpBasicAuthentication()) {
                    writer.writeStartElement(prefix, SPConstants.HTTP_BASIC_AUTHENTICATION.getLocalPart(), namespaceURI);
                    writer.writeEndElement();
                } else if (isHttpDigestAuthentication()) {
                    writer.writeStartElement(prefix, SPConstants.HTTP_DIGEST_AUTHENTICATION.getLocalPart(), namespaceURI);
                    writer.writeEndElement();
                } else if (isRequireClientCertificate()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_CLIENT_CERTIFICATE.getLocalPart(), namespaceURI);
                    writer.writeEndElement();
                }
                // </wsp:Policy>
                writer.writeEndElement();
            }
        } else {
            // RequireClientCertificate=".."
            writer.writeAttribute(SPConstants.REQUIRE_CLIENT_CERTIFICATE.getLocalPart(), Boolean
                    .toString(isRequireClientCertificate()));
        }

        writer.writeEndElement();
        // </sp:HttpsToken>
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {
    }
}
