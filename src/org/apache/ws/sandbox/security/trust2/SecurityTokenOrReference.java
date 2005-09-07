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


package org.apache.ws.sandbox.security.trust2;

import org.apache.ws.sandbox.security.trust2.exception.ElementParsingException;
import org.apache.ws.sandbox.security.trust2.exception.InvalidSecurityTokenReference;
import org.apache.ws.sandbox.security.trust2.exception.TrustException;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/**
 * @author ddelvecc
 *         <p/>
 *         A class to hold either a security token of some kind (UsernameToken, BinarySecurityToken, etc.)
 *         or a SecurityTokenReference.
 */
public class SecurityTokenOrReference {

    protected Document doc = null;

    protected SecurityTokenReference reference = null;
    protected UsernameToken usernameToken = null;
    protected BinarySecurity binarySecurityToken = null;

    protected boolean isReference;

    public boolean isReference() {
        return reference != null;
    }

    public boolean isToken() {
        return reference == null;
    }

    public SecurityTokenOrReference(Element element) throws ElementParsingException {

        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
        try {
            if (el.equals(SecurityTokenReference.SECURITY_TOKEN_REFERENCE))
                this.reference = new SecurityTokenReference(element);
            if (el.equals(UsernameToken.TOKEN))
                this.usernameToken = new UsernameToken(element);
            if (el.equals(BinarySecurity.TOKEN))
                this.binarySecurityToken = new BinarySecurity(element);
            doc = element.getOwnerDocument();
        } catch (WSSecurityException e) {
            throw new ElementParsingException("WSSecurityException while trying to create a SecurityTokenOrReference object from an XML Element: "
                    + e.getMessage());
        }
    }

    public SecurityTokenOrReference(Element element, Document doc) throws ElementParsingException {
        this(element);
        this.doc = doc;
    }

    public SecurityTokenOrReference(SecurityTokenReference reference) {
        this.reference = reference;
    }

    public SecurityTokenOrReference(UsernameToken securityToken) {
        this.usernameToken = securityToken;
    }

    public SecurityTokenOrReference(BinarySecurity securityToken) {
        this.binarySecurityToken = securityToken;
    }

    public void setDocument(Document doc) {
        this.doc = doc;
    }

    public Element getElement() {
        if (reference != null)
            return reference.getElement();
        else
            return getTokenElement();
    }

    private Element getTokenElement() {
        if (usernameToken != null)
            return usernameToken.getElement();
        if (binarySecurityToken != null)
            return binarySecurityToken.getElement();
        return null;
    }

    public Object getTokenOrReference() throws TrustException {
        if (reference != null)
            return reference;
        return resolveToken();
    }

    public Object resolveToken() throws TrustException {
        if (usernameToken != null)
            return usernameToken;
        if (binarySecurityToken != null)
            return binarySecurityToken;
        if (reference != null) {
            try {
                Element tokenElement = reference.getTokenElement(doc, null);
                if (tokenElement != null) {
                    QName el = new QName(tokenElement.getNamespaceURI(), tokenElement.getLocalName());
                    try {
                        WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
                        if (el.equals(UsernameToken.TOKEN))
                            return new UsernameToken(tokenElement);
                        if (el.equals(BinarySecurity.TOKEN))
                            return new BinarySecurity(tokenElement);
                    } catch (WSSecurityException e) {
                        throw new ElementParsingException("WSSecurityException while trying to create a SecurityToken object from a SecurityTokenReference: "
                                + e.getMessage());
                    }
                }
            } catch (WSSecurityException e) {
                throw new InvalidSecurityTokenReference("WSSecurityException while trying to dereference a <SecurityTokenReference>: " + e.getMessage());
            }
        }
        return null;
    }

    public SecurityTokenReference getReference() {
        return reference;
    }

    public UsernameToken getUsernameToken() {
        return usernameToken;
    }

    public BinarySecurity getBinarySecurity() {
        return binarySecurityToken;
    }
}
