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
import org.apache.neethi.PolicyComponent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Collection;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class RecipientToken extends AbstractSecurityAssertion implements TokenWrapper {

    private Token receipientToken;

    public RecipientToken(SPConstants spConstants) {
        setVersion(spConstants);
    }

    /**
     * @return Returns the receipientToken.
     */
    public Token getReceipientToken() {
        return receipientToken;
    }

    /**
     * @param receipientToken The receipientToken to set.
     */
    public void setReceipientToken(Token receipientToken) {
        this.receipientToken = receipientToken;
    }

    /* (non-Javadoc)
     * @see org.apache.ws.security.policy.TokenWrapper#setToken(org.apache.ws.security.policy.Token)
     */

    public void setToken(Token tok) {
        this.setReceipientToken(tok);
    }

    public QName getName() {
        return spConstants.getRecipientToken();
    }

    public PolicyComponent normalize() {
        throw new UnsupportedOperationException();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);

        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:RecipientToken>
        writer.writeStartElement(prefix, localName, namespaceURI);

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }

        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(), SPConstants.POLICY.getNamespaceURI());

        Token token = getReceipientToken();
        if (token == null) {
            throw new RuntimeException("RecipientToken doesn't contain any token assertions");
        }
        token.serialize(writer);

        // </wsp:Policy>
        writer.writeEndElement();

        // </sp:RecipientToken>
        writer.writeEndElement();
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return new SecurityEvent.Event[0];
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {
        if (receipientToken != null) {
            receipientToken.setResponsibleAssertionEvents(new SecurityEvent.Event[]{SecurityEvent.Event.RecipientEncryptionToken});
            receipientToken.getAssertions(assertionStateMap);
        }
    }

    @Override
    public boolean isAsserted(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {
        boolean isAsserted = super.isAsserted(assertionStateMap);
        if (receipientToken != null) {
            isAsserted &= receipientToken.isAsserted(assertionStateMap);
        }
        return isAsserted;
    }
}
