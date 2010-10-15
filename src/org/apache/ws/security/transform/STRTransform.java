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
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;

import org.apache.xml.security.signature.XMLSignatureInput;

import org.jcp.xml.dsig.internal.dom.ApacheData;
import org.jcp.xml.dsig.internal.dom.DOMSubTreeData;
import org.jcp.xml.dsig.internal.dom.DOMUtils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;


/**
 * Class STRTransform.
 */
public class STRTransform extends TransformService {

    public static final String TRANSFORM_URI = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

    private TransformParameterSpec params;
    
    private Element transformElement;
    
    private XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    
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
        transformElement = (Element) 
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
    }

    public void marshalParams(XMLStructure parent, XMLCryptoContext context)
    throws MarshalException {
        if (context != null && !(context instanceof DOMCryptoContext)) {
            throw new ClassCastException
                ("context must be of type DOMCryptoContext");
        }
        Element transformElement2 = (Element) 
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
        DOMUtils.appendChild(transformElement2, transformElement);
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
            Transform c14nTransform =
                signatureFactory.newTransform(
                    canonAlgo, (TransformParameterSpec)null
                );
            
            //
            // Get the input (node) to transform. Currently we support only an
            // Element as input format. If other formats are required we must
            // get it as bytes and probably reparse it into a DOM tree (How to
            // work with nodesets? how to select the right node from a nodeset?)
            //
            XMLSignatureInput xmlSignatureInput = null;
            if (data instanceof ApacheData) {
                xmlSignatureInput = ((ApacheData) data).getXMLSignatureInput();
            } else if (data instanceof DOMSubTreeData) {
                DOMSubTreeData subTree = (DOMSubTreeData) data;
                xmlSignatureInput = new XMLSignatureInput(subTree.getRoot());
                xmlSignatureInput.setExcludeComments(subTree.excludeComments());
            } else {
                try {
                    xmlSignatureInput = 
                        new XMLSignatureInput(((OctetStreamData)data).getOctetStream());
                } catch (Exception ex) {
                    throw new TransformException(ex);
                }
            }
            
            if (!xmlSignatureInput.isElement()) {
                throw new TransformException(
                    "Wrong input format - only element input supported"
                );
            }
            Element str = (Element)xmlSignatureInput.getSubNode();
            //
            // The element to transform MUST be a SecurityTokenReference
            // element.
            //
            SecurityTokenReference secRef = new SecurityTokenReference(str);
            //
            // Third and fourth step are performed by derefenceSTR()
            //
            Document doc = str.getOwnerDocument();
            WSDocInfo wsDocInfo = WSDocInfoStore.lookup(doc);
            if (wsDocInfo == null) {
                throw new TransformException("no WSDocInfo found");
            }

            Element dereferencedToken = 
                STRTransformUtil.dereferenceSTR(doc, secRef, wsDocInfo);
            //
            // According to WSS spec an Apex node must contain a default namespace.
            // 
            boolean changedNamespace = false;
            if (!dereferencedToken.hasAttribute("xmlns")) {
                dereferencedToken.setAttribute("xmlns", "");
                changedNamespace = true;
            }
            
            //
            // C14n with specified algorithm. According to WSS Specification.
            //
            boolean excludeComments = false;
            if (WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(canonAlgo)
                || WSConstants.C14N_OMIT_COMMENTS.equals(canonAlgo)) {
                excludeComments = true;
            }
            NodeSetData transformData = new DOMSubTreeData(dereferencedToken, excludeComments);
            OctetStreamData transformedData = 
                (OctetStreamData)c14nTransform.transform(transformData, xc);
            
            //
            // If a default namespace has been added, then remove it from the element
            //
            if (changedNamespace) {
                dereferencedToken.removeAttribute("xmlns");
            }
            
            XMLSignatureInput output = new XMLSignatureInput(transformedData.getOctetStream());
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

}
