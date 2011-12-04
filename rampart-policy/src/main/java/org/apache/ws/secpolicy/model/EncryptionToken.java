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

package org.apache.ws.secpolicy.model;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class EncryptionToken extends AbstractSecurityAssertion implements TokenWrapper {

    private Token encryptionToken;
    
    public EncryptionToken(int version) {
        setVersion(version);
    }

    /**
     * @return Returns the encryptionToken.
     */
    public Token getEncryptionToken() {
        return encryptionToken;
    }

    /**
     * @param encryptionToken The encryptionToken to set.
     */
    public void setEncryptionToken(Token encryptionToken) {
        this.encryptionToken = encryptionToken;
    }

    public void setToken(Token tok)  {
        this.setEncryptionToken(tok);
    }

    public QName getName() {
        if (version == SPConstants.SP_V12) {
            return SP12Constants.ENCRYPTION_TOKEN;
        } else {
            return SP11Constants.ENCRYPTION_TOKEN;
        }
        
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
        
        // <sp:EncryptionToken>
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
        
        if (encryptionToken == null) {
            throw new RuntimeException("EncryptionToken is not set");
        }
        
        encryptionToken.serialize(writer);
        
        // </wsp:Policy>
        writer.writeEndElement();
        
        // </sp:EncryptionToken>
        writer.writeEndElement();
    }
}
