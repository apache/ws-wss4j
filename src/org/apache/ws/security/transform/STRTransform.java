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

package org.apache.ws.security.transform;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.ws.security.util.Base64;
import org.apache.xml.security.utils.XMLUtils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Class STRTransform
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 * @version 1.0
 */
public class STRTransform extends TransformSpi {

    /**
     * Field implementedTransformURI
     */
    public static final String implementedTransformURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

    private static Log log = LogFactory.getLog(STRTransform.class.getName());

    private static boolean doDebug = false;

    private static String XMLNS = "xmlns=";

    private WSDocInfo wsDocInfo = null;

    public boolean wantsOctetStream() {
        return false;
    }

    public boolean wantsNodeSet() {
        return true;
    }

    public boolean returnsOctetStream() {
        return true;
    }

    public boolean returnsNodeSet() {
        return false;
    }

    /**
     * Method engineGetURI
     */
    protected String engineGetURI() {
        return STRTransform.implementedTransformURI;
    }

    /**
     * Method enginePerformTransform
     * 
     * @param input
     * @throws CanonicalizationException
     * @throws InvalidCanonicalizerException
     */
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input)
            throws IOException, CanonicalizationException,
            InvalidCanonicalizerException {

        doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("Beginning STRTransform..." + input.toString());
        }

        try {

            /*
             * Get the main document, that is the complete SOAP request document
             */
            Document thisDoc = this._transformObject.getDocument();
            int docHash = thisDoc.hashCode();
            if (doDebug) {
                log.debug("doc: " + thisDoc.toString() + ", " + docHash);
            }

            /*
             * Here we get some information about the document that is being
             * processed, in particular the crypto implementation, and already
             * detected BST that may be used later during dereferencing.
             */
            wsDocInfo = WSDocInfoStore.lookup(docHash);
            if (wsDocInfo == null) {
                throw (new CanonicalizationException("no WSDocInfo found"));
            }

            /*
             * According to the OASIS WS Specification "Web Services Security:
             * SOAP Message Security 1.0" Monday, 19 January 2004, chapter 8.3
             * describes that the input node set must be processed by the c14n
             * that is specified in the argument element of the STRTransform
             * element.
             * 
             * First step: Get the required c14n argument and get the specified
             * Canonicalizer
             */

            String canonAlgo = null;
            if (this._transformObject.length(WSConstants.WSSE_NS,
                    "TransformationParameters") == 1) {
                Element tmpE = XMLUtils.selectNode(this._transformObject
                        .getElement().getFirstChild(), WSConstants.WSSE_NS,
                        "TransformationParameters", 0);
                Element canonElem = (Element) WSSecurityUtil.getDirectChild(
                        tmpE, "CanonicalizationMethod", WSConstants.SIG_NS);
                canonAlgo = canonElem.getAttribute("Algorithm");
                if (doDebug) {
                    log.debug("CanonAlgo: " + canonAlgo);
                }
            }
            Canonicalizer canon = Canonicalizer.getInstance(canonAlgo);

            ByteArrayOutputStream bos = null;
            byte[] buf = null;
            if (doDebug) {
                buf = input.getBytes();
                bos = new ByteArrayOutputStream(buf.length);
                bos.write(buf, 0, buf.length);
                log.debug("canon bos: " + bos.toString());
            }

            /*
             * Get the input (node) to transform. Currently we support only an
             * Element as input format. If other formats are required we must
             * get it as bytes and probably reparse it into a DOM tree (How to
             * work with nodesets? how to select the right node from a nodeset?)
             */
            Element str = null;
            if (input.isElement()) {
                str = (Element) input.getSubNode();
            } else {
                throw (new CanonicalizationException(
                        "Wrong input format - only element input supported"));
            }

            if (doDebug) {
                log.debug("STR: " + str.toString());
            }
            /*
             * The element to transform MUST be a SecurityTokenReference
             * element.
             */
            SecurityTokenReference secRef = new SecurityTokenReference(str);
            /*
             * Third and forth step are performed by derefenceSTR()
             */
            Element dereferencedToken = dereferenceSTR(thisDoc, secRef);
            /*
             * C14n with specified algorithm. According to WSS Specification.
             */
            buf = canon.canonicalizeSubtree(dereferencedToken, "#default");
            if (doDebug) {
                bos = new ByteArrayOutputStream(buf.length);
                bos.write(buf, 0, buf.length);
                log.debug("after c14n: " + bos.toString());
            }

            /*
             * Alert: Hacks ahead According to WSS spec an Apex node must
             * contain a default namespace. If none is availabe in the first
             * node of the c14n output (this is the apex element) then we do
             * some editing to insert an empty default namespace
             * 
             * TODO: Rework theses hacks after c14n was updated and can be
             * instructed to insert empty default namespace if required
             */
            // If the problem with c14n method is solved then just do:
            // return new XMLSignatureInput(buf);
            
            // start of HACK
            StringBuffer bf = new StringBuffer(new String(buf));
            String bf1 = bf.toString();

            /*
             * Find start and end of first element <....>, this is the Apex node
             */
            int lt = bf1.indexOf("<");
            int gt = bf1.indexOf(">");
            /*
             * Lookup the default namespace
             */
            int idx = bf1.indexOf(XMLNS);
            /*
             * If none found or if it is outside of this (Apex) element look for
             * first blank in, insert default namespace there (this is the
             * correct place according to c14n specification)
             */
            if (idx < 0 || idx > gt) {
                idx = bf1.indexOf(" ");
                bf.insert(idx + 1, "xmlns=\"\" ");
                bf1 = bf.toString();
            }
            if (doDebug) {
                log.debug("last result: ");
                log.debug(bf1);
            }
            return new XMLSignatureInput(bf1.getBytes());
        }
        // End of HACK
        catch (WSSecurityException ex) {
            throw (new CanonicalizationException("WS Security Exception", ex));

        }
    }

    private Element dereferenceSTR(Document doc, SecurityTokenReference secRef)
            throws  WSSecurityException {

        /*
         * Third step: locate the security token referenced by the STR element.
         * Either the Token is contained in the document as a
         * BinarySecurityToken or stored in some key storage.
         * 
         * Forth step: after security token was located, prepare it. If its
         * reference via a direct reference, i.e. a relative URI that references
         * the BST directly in the message then just return that element.
         * Otherwise wrap the located token in a newly created BST element as
         * described in WSS Specification.
         * 
         */
        Element tokElement = null;

        /*
         * First case: direct reference, according to chap 7.2 of OASIS WS
         * specification (main document). Only in this case return a true
         * reference to the BST. Copying is done by the caller.
         */
        if (secRef.containsReference()) {
            if (doDebug) {
                log.debug("STR: Reference");
            }
            tokElement = secRef.getTokenElement(doc, wsDocInfo, null);
        }
        /*
         * second case: IssuerSerial, lookup in keystore, wrap in BST according
         * to specification
         */
        else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            if (doDebug) {
                log.debug("STR: IssuerSerial");
            }
            X509Certificate cert = null;
            X509Certificate[] certs = secRef.getX509IssuerSerial(wsDocInfo
                    .getCrypto());
            if (certs == null || certs.length == 0 || certs[0] == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
            cert = certs[0];
            tokElement = createBSTX509(doc, cert, secRef.getElement());
        }
        /*
         * third case: KeyIdentifier, must be SKI, lookup in keystore, wrap in
         * BST according to specification. No other KeyIdentifier type handled
         * here - just SKI
         */
        else if (secRef.containsKeyIdentifier()) {
            if (doDebug) {
                log.debug("STR: KeyIdentifier");
            }
            X509Certificate cert = null;
            X509Certificate[] certs = secRef.getKeyIdentifier(wsDocInfo
                    .getCrypto());
            if (certs == null || certs.length == 0 || certs[0] == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
            cert = certs[0];
            tokElement = createBSTX509(doc, cert, secRef.getElement());
        }
        return (Element) tokElement;
    }

    private Element createBSTX509(Document doc, X509Certificate cert,
            Element secRefE) throws WSSecurityException {

        byte data[];
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
            "encodeError");
        }
        String prefix = WSSecurityUtil
                .getPrefixNS(WSConstants.WSSE_NS, secRefE);
        Element elem = doc.createElementNS(WSConstants.WSSE_NS, prefix
                + ":BinarySecurityToken");
        WSSecurityUtil.setNamespace(elem, WSConstants.WSSE_NS, prefix);
        // elem.setAttributeNS(WSConstants.XMLNS_NS, "xmlns", "");
        if (cert.getVersion() == 1) {
            elem.setAttributeNS(null, "ValueType", X509Security.X509_V1_TYPE);
        } else {
            elem.setAttributeNS(null, "ValueType", X509Security.X509_V3_TYPE);
        }
        Text certText = doc.createTextNode(Base64.encode(data)); // no line
                                                                    // wrap
        elem.appendChild(certText);
        return elem;
    }
}
