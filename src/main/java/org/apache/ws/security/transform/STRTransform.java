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

package org.apache.ws.security.transform;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignatureInput;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Iterator;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;


/**
 * Class STRTransform.
 */
public class STRTransform extends TransformService {

    public static final String TRANSFORM_URI = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";
    
    public static final String TRANSFORM_WS_DOC_INFO = "transform_ws_doc_info";

    private TransformParameterSpec params;
    
    private Element transformElement;
    
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(STRTransform.class);

    private static boolean doDebug = false;
    
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }
    
    public void init(TransformParameterSpec params)
        throws InvalidAlgorithmParameterException {
        this.params = params;
    }
    
    public void init(XMLStructure parent, XMLCryptoContext context)
    throws InvalidAlgorithmParameterException {
        if (context != null && !(context instanceof DOMCryptoContext)) {
            throw new ClassCastException
                ("context must be of type DOMCryptoContext");
        }
        if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("parent must be of type DOMStructure");
        }
        transformElement = (Element) 
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
    }

    public void marshalParams(XMLStructure parent, XMLCryptoContext context)
    throws MarshalException {
        if (context != null && !(context instanceof DOMCryptoContext)) {
            throw new ClassCastException
                ("context must be of type DOMCryptoContext");
        }
        if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("parent must be of type DOMStructure");
        }
        Element transformElement2 = (Element) 
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
        appendChild(transformElement2, transformElement);
        transformElement = transformElement2;
    }

    
    public Data transform(Data data, XMLCryptoContext xc) 
        throws TransformException {
        if (data == null) {
            throw new NullPointerException("data must not be null");
        }
        return transformIt(data, xc, null);
    }

    public Data transform(Data data, XMLCryptoContext xc, OutputStream os) 
        throws TransformException {
        if (data == null) {
            throw new NullPointerException("data must not be null");
        }
        if (os == null) {
            throw new NullPointerException("output stream must not be null");
        }
        return transformIt(data, xc, os);
    }
    
    
    private Data transformIt(Data data, XMLCryptoContext xc, OutputStream os) 
        throws TransformException {
        doDebug = log.isDebugEnabled();
        // 
        // First step: Get the required c14n argument and get the specified
        // Canonicalizer
        //
        String canonAlgo = null;
        Element transformParams = WSSecurityUtil.getDirectChildElement(
            transformElement, "TransformationParameters", WSConstants.WSSE_NS
        );
        if (transformParams != null) {
            Element canonElem = 
                WSSecurityUtil.getDirectChildElement(
                    transformParams, "CanonicalizationMethod", WSConstants.SIG_NS
                );
            canonAlgo = canonElem.getAttribute("Algorithm");
        }
        try {
            //
            // Get the input (node) to transform. 
            //
            Element str = null;
            if (data instanceof NodeSetData) {
                NodeSetData nodeSetData = (NodeSetData)data;
                Iterator<?> iterator = nodeSetData.iterator();
                while (iterator.hasNext()) {
                    Node node = (Node)iterator.next();
                    if (node instanceof Element && "SecurityTokenReference".equals(node.getLocalName())) {
                        str = (Element)node;
                        break;
                    }
                }
            } else {
                try {
                    XMLSignatureInput xmlSignatureInput = 
                        new XMLSignatureInput(((OctetStreamData)data).getOctetStream());
                    str = (Element)xmlSignatureInput.getSubNode();
                } catch (Exception ex) {
                    throw new TransformException(ex);
                }
            }
            if (str == null) {
                throw new TransformException("No SecurityTokenReference found");
            }
            //
            // The element to transform MUST be a SecurityTokenReference
            // element.
            //
            SecurityTokenReference secRef = new SecurityTokenReference(str);
            
            Canonicalizer canon = Canonicalizer.getInstance(canonAlgo);

            ByteArrayOutputStream bos = null;
            byte[] buf = null;
            
            //
            // Third and fourth step are performed by dereferenceSTR()
            //
            Object wsDocInfoObject = xc.getProperty(TRANSFORM_WS_DOC_INFO);
            WSDocInfo wsDocInfo = null;
            if (wsDocInfoObject instanceof WSDocInfo) {
                wsDocInfo = (WSDocInfo)wsDocInfoObject;
            }
            if (wsDocInfo == null && doDebug) {
                log.debug("STRTransform: no WSDocInfo found");
            }

            Document doc = str.getOwnerDocument();
            Element dereferencedToken = 
                STRTransformUtil.dereferenceSTR(doc, secRef, wsDocInfo);
            
            if (dereferencedToken != null) {
                String type = dereferencedToken.getAttribute("ValueType");
                if ((X509Security.X509_V3_TYPE.equals(type) 
                    || PKIPathSecurity.getType().equals(type))) {
                    //
                    // Add the WSSE/WSU namespaces to the element for C14n
                    //
                    WSSecurityUtil.setNamespace(
                        dereferencedToken, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX
                    );
                    WSSecurityUtil.setNamespace(
                        dereferencedToken, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                    );
                }
            }
            
            //
            // C14n with specified algorithm. According to WSS Specification.
            //
            buf = canon.canonicalizeSubtree(dereferencedToken, "#default");
            if (doDebug) {
                bos = new ByteArrayOutputStream(buf.length);
                bos.write(buf, 0, buf.length);
                log.debug("after c14n: " + bos.toString());
            }

            //
            // Alert: Hacks ahead According to WSS spec an Apex node must
            // contain a default namespace. If none is availabe in the first
            // node of the c14n output (this is the apex element) then we do
            // some editing to insert an empty default namespace
            // 
            // TODO: Rework theses hacks after c14n was updated and can be
            // instructed to insert empty default namespace if required
            //
            // If the problem with c14n method is solved then just do:
            // return new XMLSignatureInput(buf);
            
            // start of HACK
            StringBuilder bf = new StringBuilder(new String(buf));
            String bf1 = bf.toString();

            //
            // Find start and end of first element <....>, this is the Apex node
            //
            int gt = bf1.indexOf('>');
            //
            // Lookup the default namespace
            //
            int idx = bf1.indexOf("xmlns=");
            //
            // If none found or if it is outside of this (Apex) element look for
            // first blank in, insert default namespace there (this is the
            // correct place according to c14n specification)
            //
            if (idx < 0 || idx > gt) {
                idx = bf1.indexOf(' ');
                bf.insert(idx + 1, "xmlns=\"\" ");
                bf1 = bf.toString();
            }
            if (doDebug) {
                log.debug("last result: ");
                log.debug(bf1);
            }
            XMLSignatureInput output = new XMLSignatureInput(bf1.getBytes());
            if (os != null) {
                output.updateOutputStream(os);
                return null;
            }
            return new OctetStreamData(output.getOctetStream());
        } catch (Exception ex) {
            throw new TransformException(ex);
        }
    }
    
    
    public final boolean isFeatureSupported(String feature) {
        if (feature == null) {
            throw new NullPointerException();
        } else {
            return false;
        }
    }
    
    private static void appendChild(Node parent, Node child) {
        Document ownerDoc = null;
        if (parent.getNodeType() == Node.DOCUMENT_NODE) {
            ownerDoc = (Document)parent;
        } else {
            ownerDoc = parent.getOwnerDocument();
        }
        if (child.getOwnerDocument() != ownerDoc) {
            parent.appendChild(ownerDoc.importNode(child, true));
        } else {
            parent.appendChild(child);
        }
    }

}
