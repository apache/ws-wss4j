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

package org.apache.ws.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.jcp.xml.dsig.internal.dom.DOMSubTreeData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class XMLUtils {
    
    private static final Log log = LogFactory.getLog(XMLUtils.class.getName());
    private static final boolean doDebug = log.isDebugEnabled();
    
    public static String PrettyDocumentToString(Document doc) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ElementToStream(doc.getDocumentElement(), baos);
        return new String(baos.toByteArray());
    }

    public static void ElementToStream(Element element, OutputStream out) {
        try {
            DOMSource source = new DOMSource(element);
            StreamResult result = new StreamResult(out);
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            transformer.transform(source, result);
        } catch (Exception ex) {
            if (doDebug) {
                log.debug(ex.getMessage(), ex);
            }
        }
    }

    /**
     * Utility to get the bytes uri
     *
     * @param source the resource to get
     */
    public static InputSource sourceToInputSource(Source source) {
        if (source instanceof SAXSource) {
            return ((SAXSource) source).getInputSource();
        } else if (source instanceof DOMSource) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Node node = ((DOMSource) source).getNode();
            if (node instanceof Document) {
                node = ((Document) node).getDocumentElement();
            }
            Element domElement = (Element) node;
            ElementToStream(domElement, baos);
            InputSource isource = new InputSource(source.getSystemId());
            isource.setByteStream(new ByteArrayInputStream(baos.toByteArray()));
            return isource;
        } else if (source instanceof StreamSource) {
            StreamSource ss = (StreamSource) source;
            InputSource isource = new InputSource(ss.getSystemId());
            isource.setByteStream(ss.getInputStream());
            isource.setCharacterStream(ss.getReader());
            isource.setPublicId(ss.getPublicId());
            return isource;
        } else {
            return getInputSourceFromURI(source.getSystemId());
        }
    }

    /**
     * Utility to get the bytes uri.
     * Does NOT handle authenticated URLs,
     * use getInputSourceFromURI(uri, username, password)
     *
     * @param uri the resource to get
     */
    public static InputSource getInputSourceFromURI(String uri) {
        return new InputSource(uri);
    }
    
    /**
     * Outputs a DOM tree to an {@link OutputStream}. <I>If an Exception is
     * thrown during execution, it's StackTrace is output to System.out, but the
     * Exception is not re-thrown.</I>
     *
     * @param contextNode root node of the DOM tree
     * @param os the {@link OutputStream}
     * @param addPreamble
     */
    public static void outputDOM(Node contextNode, OutputStream os, boolean addPreamble) {

       try {
          if (addPreamble) {
             os.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n".getBytes());
          }

          XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
          Transform c14nTransform =
              signatureFactory.newTransform(
                  WSConstants.C14N_WITH_COMMENTS, (TransformParameterSpec)null
              );
          
          NodeSetData transformData = new DOMSubTreeData(contextNode, false);
          OctetStreamData transformedData = 
              (OctetStreamData)c14nTransform.transform(transformData, null);
          
          InputStream in = transformedData.getOctetStream();
          int nextChar;
          while ((nextChar = in.read()) != -1) {
              os.write(nextChar);
          }
          os.flush();
          in.close();
       } catch (IOException e) {
           e.printStackTrace();
       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (InvalidAlgorithmParameterException e) {
           e.printStackTrace();
       } catch (TransformException e) {
           e.printStackTrace();
       }
    }
    
}
