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

import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;

public class UsernameToken extends Token {

    private boolean useUTProfile10 = false;

    private boolean useUTProfile11 = false;
    
    private boolean noPassword;
    
    private boolean hashPassword;
    
    public UsernameToken(int version){
        setVersion(version);
    }

    /**
     * @return Returns the useUTProfile11.
     */
    public boolean isUseUTProfile11() {
        return useUTProfile11;
    }

    /**
     * @param useUTProfile11
     *            The useUTProfile11 to set.
     */
    public void setUseUTProfile11(boolean useUTProfile11) {
        this.useUTProfile11 = useUTProfile11;
    }
    
    public boolean isNoPassword() {
        return noPassword;
    }
    
    public void setNoPassword(boolean noPassword) {
        this.noPassword = noPassword;
    }
    
    public boolean isHashPassword() {
        return hashPassword;
    }
    
    public void setHashPassword(boolean hashPassword) {
        this.hashPassword = hashPassword;
    }

    public boolean isUseUTProfile10() {
        return useUTProfile10;
    }

    public void setUseUTProfile10(boolean useUTProfile10) {
        this.useUTProfile10 = useUTProfile10;
    }

    public QName getName() {
        if (version == SPConstants.SP_V12) {
            return SP12Constants.USERNAME_TOKEN;
        } else {
            return SP11Constants.USERNAME_TOKEN;
        }
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

        // <sp:UsernameToken
        writer.writeStartElement(prefix, localname, namespaceURI);

        writer.writeNamespace(prefix, namespaceURI);

        String inclusion;
        
        if (version == SPConstants.SP_V12) {
            inclusion = SP12Constants.getAttributeValueFromInclusion(getInclusion());
        } else {
            inclusion = SP11Constants.getAttributeValueFromInclusion(getInclusion()); 
        }

        if (inclusion != null) {
            writer.writeAttribute(prefix, namespaceURI, SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
        }

        if (isUseUTProfile10() || isUseUTProfile11()) {
            String pPrefix = writer.getPrefix(SPConstants.POLICY
                    .getNamespaceURI());
            if (pPrefix == null) {
                writer.setPrefix(SPConstants.POLICY.getPrefix(), SPConstants.POLICY
                        .getNamespaceURI());
            }

            // <wsp:Policy>
            writer.writeStartElement(prefix, SPConstants.POLICY.getLocalPart(),
                    SPConstants.POLICY.getNamespaceURI());

            // CHECKME
            if (isUseUTProfile10()) {
                // <sp:WssUsernameToken10 />
                writer.writeStartElement(prefix, SPConstants.USERNAME_TOKEN10 , namespaceURI);
            } else {
                // <sp:WssUsernameToken11 />
                writer.writeStartElement(prefix, SPConstants.USERNAME_TOKEN11 , namespaceURI);
            }
            
            if (version == SPConstants.SP_V12) {
                
                if (isNoPassword()) {
                    writer.writeStartElement(prefix, SPConstants.NO_PASSWORD, namespaceURI);
                    writer.writeEndElement();    
                } else if (isHashPassword()){
                    writer.writeStartElement(prefix, SPConstants.HASH_PASSWORD, namespaceURI);
                    writer.writeEndElement(); 
                }
                
                if (isDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();  
                } else if (isExplicitDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_EXPLICIT_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();  
                } else if (isImpliedDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_IMPLIED_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();  
                }
                
            }
            writer.writeEndElement();

            // </wsp:Policy>
            writer.writeEndElement();

        }

        writer.writeEndElement();
        // </sp:UsernameToken>

    }
}
