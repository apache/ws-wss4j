/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.common.dom.transform;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.dom.WSDocInfo;
import org.apache.wss4j.common.dom.callback.CallbackLookup;
import org.apache.wss4j.common.dom.callback.DOMCallbackLookup;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * Utility class exposing the dereferencing LOG.c of the {@link STRTransform} implementation.
 */
public final class STRTransformUtil {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(STRTransformUtil.class);

    /**
     * Retrieves the element representing the referenced content of a STR.
     *
     * @return the element representing the referenced content. The element is either
     *         extracted from {@code doc} or a new element is created in the
     *         case of a key identifier or issuer serial STR.  {@code null} if
     *         {@code secRef} does not contain a direct reference, key identifier, or
     *         issuer serial.
     * @throws WSSecurityException
     *             If an issuer serial or key identifier is used in the STR and
     *             the certificate cannot be resolved from the crypto
     *             configuration or if there is an error working with the resolved
     *             cert
     */
    public static Element dereferenceSTR(Document doc,
            SecurityTokenReference secRef, WSDocInfo wsDocInfo) throws WSSecurityException {
        //
        // First case: direct reference, according to chap 7.2 of OASIS WS
        // specification (main document). Only in this case return a true
        // reference to the BST or Assertion. Copying is done by the caller.
        //
        if (secRef.containsReference()) {
            LOG.debug("STR: Reference");

            Reference reference = secRef.getReference();
            return getTokenElement(doc, wsDocInfo, null, reference.getURI(), reference.getValueType());
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            //
            // second case: IssuerSerial, lookup in keystore, wrap in BST according
            // to specification
            //
            LOG.debug("STR: IssuerSerial");
            X509Certificate[] certs =
                secRef.getX509IssuerSerial(wsDocInfo.getCrypto());
            if (certs == null || certs.length == 0 || certs[0] == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
            }
            return createBSTX509(doc, certs[0], secRef.getElement(), secRef.getKeyIdentifierEncodingType());
        } else if (secRef.containsKeyIdentifier()) {
            //
            // third case: KeyIdentifier. For SKI, lookup in keystore, wrap in
            // BST according to specification. Otherwise if it's a wsse:KeyIdentifier it could
            // be a SAML assertion, so try and find the referenced element.
            //
            LOG.debug("STR: KeyIdentifier");
            if (WSS4JConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSS4JConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                return getTokenElement(doc, wsDocInfo, null, secRef.getKeyIdentifierValue(),
                                                     secRef.getKeyIdentifierValueType());
            } else {
                X509Certificate[] certs = secRef.getKeyIdentifier(wsDocInfo.getCrypto());
                if (certs == null || certs.length == 0 || certs[0] == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                return createBSTX509(doc, certs[0], secRef.getElement());
            }
        }
        return null;
    }

    public static Element createBSTX509(Document doc, X509Certificate cert, Element secRefE)
        throws WSSecurityException {
        return createBSTX509(doc, cert, secRefE, null);
    }

    public static Element createBSTX509(Document doc, X509Certificate cert, Element secRefE,
                                        String secRefEncType)
        throws WSSecurityException {
        byte[] data;
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, e, "encodeError"
            );
        }
        String prefix = XMLUtils.getPrefixNS(WSS4JConstants.WSSE_NS, secRefE);
        if (prefix == null) {
            prefix = WSS4JConstants.WSSE_PREFIX;
        }
        Element elem = doc.createElementNS(WSS4JConstants.WSSE_NS, prefix + ":BinarySecurityToken");
        XMLUtils.setNamespace(elem, WSS4JConstants.WSSE_NS, prefix);
        // elem.setAttributeNS(WSConstants.XMLNS_NS, "xmlns", "");
        elem.setAttributeNS(null, "ValueType", X509Security.X509_V3_TYPE);
        if (secRefEncType != null) {
            elem.setAttributeNS(null, "EncodingType", secRefEncType);
        }
        Text certText = doc.createTextNode(org.apache.xml.security.utils.XMLUtils.encodeToString(data)); // no line wrap
        elem.appendChild(certText);
        return elem;
    }

    /**
     * Hidden in utility class.
     */
    private STRTransformUtil() {
    }

    //
    // TODO This was copied from STRParserUtil, remove once/if we copy that across to this module
    //

    private static Element getTokenElement(
        Document doc, WSDocInfo docInfo, CallbackHandler cb,
        String uri, String valueType
    ) throws WSSecurityException {
        LOG.debug("Token reference uri: {}", uri);
        LOG.debug("Token reference ValueType: {}", valueType);

        if (uri == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY, "badReferenceURI"
            );
        }

        Element tokElement =
            findProcessedTokenElement(doc, docInfo, cb, uri, valueType);
        if (tokElement == null) {
            tokElement = findUnprocessedTokenElement(doc, docInfo, uri, valueType);
        }

        if (tokElement == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE,
                "noToken", new Object[] {uri});
        }
        return tokElement;
    }

    /**
     * Find a token that has not been processed already - in other words, it searches for
     * the element, rather than trying to access previous results to find the element
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    private static Element findUnprocessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = XMLUtils.getIDFromReference(uri);
        //
        // Delegate finding the element to the CallbackLookup instance
        //
        CallbackLookup callbackLookup = null;
        if (docInfo != null) {
            callbackLookup = docInfo.getCallbackLookup();
        }
        if (callbackLookup == null) {
            callbackLookup = new DOMCallbackLookup(doc);
        }
        return callbackLookup.getElement(id, type, true);
    }

    /**
     * Find a token that has been processed already - in other words, it access previous
     * results to find the element, rather than conducting a general search
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param cb CallbackHandler instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    private static Element findProcessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        CallbackHandler cb,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = XMLUtils.getIDFromReference(uri);
        //
        // Try to find it from the WSDocInfo instance first
        //
        if (docInfo != null) {
            Element token = docInfo.getTokenElement(id);
            if (token != null) {
                return token;
            }
        }

        //
        // Try to find a custom token
        //
        if (cb != null && (WSS4JConstants.WSC_SCT.equals(type)
            || WSS4JConstants.WSC_SCT_05_12.equals(type)
            || WSS4JConstants.WSS_SAML_KI_VALUE_TYPE.equals(type)
            || WSS4JConstants.WSS_SAML2_KI_VALUE_TYPE.equals(type)
            || isKerberosToken(type))) {
            //try to find a custom token
            WSPasswordCallback pwcb =
                new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
            try {
                cb.handle(new Callback[]{pwcb});
                Element assertionElem = pwcb.getCustomToken();
                if (assertionElem != null) {
                    return (Element)doc.importNode(assertionElem, true);
                }
            } catch (Exception e) {
                LOG.debug(e.getMessage(), e);
                // Consume this failure
            }
        }
        return null;
    }

    /**
     * Return true if the valueType represents a Kerberos Token
     * @param valueType the valueType of the token
     * @return true if the valueType represents a Kerberos Token
     */
    private static boolean isKerberosToken(String valueType) {
        return WSS4JConstants.WSS_KRB_V5_AP_REQ.equals(valueType)
            || WSS4JConstants.WSS_GSS_KRB_V5_AP_REQ.equals(valueType)
            || WSS4JConstants.WSS_KRB_V5_AP_REQ1510.equals(valueType)
            || WSS4JConstants.WSS_GSS_KRB_V5_AP_REQ1510.equals(valueType)
            || WSS4JConstants.WSS_KRB_V5_AP_REQ4120.equals(valueType)
            || WSS4JConstants.WSS_GSS_KRB_V5_AP_REQ4120.equals(valueType);
    }
}
