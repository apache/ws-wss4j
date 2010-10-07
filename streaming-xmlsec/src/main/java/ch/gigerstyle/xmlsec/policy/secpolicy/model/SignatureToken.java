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

package ch.gigerstyle.xmlsec.policy.secpolicy.model;

import ch.gigerstyle.xmlsec.policy.assertionStates.AssertionState;
import ch.gigerstyle.xmlsec.policy.secpolicy.SPConstants;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Collection;
import java.util.Map;

public class SignatureToken extends AbstractSecurityAssertion implements TokenWrapper {

    private Token signatureToken;

    public SignatureToken(SPConstants spConstants) {
        setVersion(spConstants);
    }

    /**
     * @return Returns the signatureToken.
     */
    public Token getSignatureToken() {
        return signatureToken;
    }

    /**
     * @param signatureToken The signatureToken to set.
     */
    public void setSignatureToken(Token signatureToken) {
        this.signatureToken = signatureToken;
    }

    public void setToken(Token tok) {
        this.setSignatureToken(tok);
    }

    public QName getName() {
        return spConstants.getSignatureToken();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {

        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix;
        String writerPrefix = writer.getPrefix(namespaceURI);

        if (writerPrefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);

        } else {
            prefix = writerPrefix;
        }

        // <sp:SignatureToken>
        writer.writeStartElement(prefix, localname, namespaceURI);

        if (writerPrefix == null) {
            // xmlns:sp=".."
            writer.writeNamespace(prefix, namespaceURI);
        }


        String wspNamespaceURI = SPConstants.POLICY.getNamespaceURI();

        String wspPrefix;

        String wspWriterPrefix = writer.getPrefix(wspNamespaceURI);

        if (wspWriterPrefix == null) {
            wspPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(wspPrefix, wspNamespaceURI);

        } else {
            wspPrefix = wspWriterPrefix;
        }

        // <wsp:Policy>
        writer.writeStartElement(wspPrefix, SPConstants.POLICY.getLocalPart(), wspNamespaceURI);

        if (wspWriterPrefix == null) {
            // xmlns:wsp=".."
            writer.writeNamespace(wspPrefix, wspNamespaceURI);
        }

        if (signatureToken == null) {
            throw new RuntimeException("EncryptionToken is not set");
        }

        signatureToken.serialize(writer);

        // </wsp:Policy>
        writer.writeEndElement();

        // </sp:SignatureToken>
        writer.writeEndElement();
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        //todo
        return new SecurityEvent.Event[0];
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {
        //todo
    }

    /*
    @Override
    public void assertPolicy(SecurityEvent securityEvent) throws PolicyViolationException {
    }

    @Override
    public boolean isAsserted() {
        return true;
    }
    */
}
