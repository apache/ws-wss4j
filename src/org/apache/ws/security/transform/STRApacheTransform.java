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

import org.jcp.xml.dsig.internal.dom.ApacheTransform;
import org.jcp.xml.dsig.internal.dom.DOMUtils;

import org.w3c.dom.Element;

import java.security.InvalidAlgorithmParameterException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;


/**
 * Class STRApacheTransform.
 */
public class STRApacheTransform extends ApacheTransform {

    public static final String TRANSFORM_URI = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

    private Element elem;
    
    public void init(TransformParameterSpec params)
        throws InvalidAlgorithmParameterException {

        this.params = params;
    }

    public void init(XMLStructure parent, XMLCryptoContext context)
        throws InvalidAlgorithmParameterException {

        super.init(parent, context);
        elem = transformElem;
    }
    
    public void marshalParams(XMLStructure parent, XMLCryptoContext context)
        throws MarshalException {

        super.marshalParams(parent, context);
        DOMUtils.appendChild(transformElem, elem);
    }

}
