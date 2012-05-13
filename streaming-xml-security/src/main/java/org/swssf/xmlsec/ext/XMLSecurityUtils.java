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
package org.swssf.xmlsec.ext;

import org.swssf.xmlsec.config.TransformerAlgorithmMapper;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLSecurityUtils {

    protected XMLSecurityUtils() {
    }

    /**
     * Returns the Id reference without the leading #
     *
     * @param reference The reference on which to drop the #
     * @return The reference without a leading #
     */
    public static String dropReferenceMarker(String reference) {
        if (reference.startsWith("#")) {
            return reference.substring(1);
        }
        return reference;
    }

    /**
     * Returns the XMLEvent type in String form
     *
     * @param xmlEvent
     * @return The XMLEvent type as string representation
     */
    public static String getXMLEventAsString(XMLEvent xmlEvent) {
        int eventType = xmlEvent.getEventType();

        switch (eventType) {
            case XMLEvent.START_ELEMENT:
                return "START_ELEMENT";
            case XMLEvent.END_ELEMENT:
                return "END_ELEMENT";
            case XMLEvent.PROCESSING_INSTRUCTION:
                return "PROCESSING_INSTRUCTION";
            case XMLEvent.CHARACTERS:
                return "CHARACTERS";
            case XMLEvent.COMMENT:
                return "COMMENT";
            case XMLEvent.START_DOCUMENT:
                return "START_DOCUMENT";
            case XMLEvent.END_DOCUMENT:
                return "END_DOCUMENT";
            case XMLEvent.ATTRIBUTE:
                return "ATTRIBUTE";
            case XMLEvent.DTD:
                return "DTD";
            case XMLEvent.NAMESPACE:
                return "NAMESPACE";
            default:
                throw new IllegalArgumentException("Illegal XMLEvent received: " + eventType);
        }
    }

    /**
     * Executes the Callback handling. Typically used to fetch passwords
     *
     * @param callbackHandler
     * @param callback
     * @throws XMLSecurityException if the callback couldn't be executed
     */
    public static void doPasswordCallback(CallbackHandler callbackHandler, Callback callback) throws XMLSecurityException {
        if (callbackHandler == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noCallback");
        }
        try {
            callbackHandler.handle(new Callback[]{callback});
        } catch (IOException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noPassword", e);
        } catch (UnsupportedCallbackException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noPassword", e);
        }
    }

    /**
     * Try to get the secret key from a CallbackHandler implementation
     *
     * @param callbackHandler a CallbackHandler implementation
     * @return An array of bytes corresponding to the secret key (can be null)
     * @throws XMLSecurityException
     */
    public static void doSecretKeyCallback(CallbackHandler callbackHandler, Callback callback, String id) throws XMLSecurityException {
        if (callbackHandler != null) {
            try {
                callbackHandler.handle(new Callback[]{callback});
            } catch (IOException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noPassword", e);
            } catch (UnsupportedCallbackException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noPassword", e);
            }
        }
    }

    public static Class loadClass(String className) throws ClassNotFoundException {
        return Thread.currentThread().getContextClassLoader().loadClass(className);
    }

    @SuppressWarnings("unchecked")
    public static final XMLEvent createXMLEventNS(final XMLEvent xmlEvent, final Deque<List<ComparableNamespace>> nsStack, final Deque<List<ComparableAttribute>> attrStack) {
        if (xmlEvent.isStartElement()) {
            final StartElement startElement = xmlEvent.asStartElement();
            final QName startElementName = startElement.getName();
            final String startElementNamePrefix = startElementName.getPrefix();

            Set<String> prefixSet = new HashSet<String>();
            prefixSet.add(startElementNamePrefix);

            List<ComparableNamespace> comparableNamespaceList = new ArrayList<ComparableNamespace>();

            ComparableNamespace curElementNamespace = new ComparableNamespace(startElementNamePrefix, startElementName.getNamespaceURI());
            comparableNamespaceList.add(curElementNamespace);

            @SuppressWarnings("unchecked")
            Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
            while (namespaceIterator.hasNext()) {
                final Namespace namespace = namespaceIterator.next();
                final String prefix = namespace.getPrefix();
                final String namespaceURI = namespace.getNamespaceURI();

                if ((prefix == null || prefix.isEmpty())
                        && (namespaceURI == null || namespaceURI.isEmpty())) {
                    continue;
                }

                if (!prefixSet.contains(prefix)) {
                    prefixSet.add(prefix);
                    comparableNamespaceList.add(new ComparableNamespace(prefix, namespaceURI));
                }
            }

            List<ComparableAttribute> comparableAttributeList;

            @SuppressWarnings("unchecked")
            Iterator<Attribute> attributeIterator = startElement.getAttributes();
            if (attributeIterator.hasNext()) {
                comparableAttributeList = new ArrayList<ComparableAttribute>();
            } else {
                comparableAttributeList = Collections.emptyList();
            }

            while (attributeIterator.hasNext()) {
                final Attribute attribute = attributeIterator.next();
                final QName attributeName = attribute.getName();
                final String prefix = attributeName.getPrefix();
                final String attributeNameNamespaceURI = attributeName.getNamespaceURI();

                if (prefix != null && prefix.isEmpty() && attributeNameNamespaceURI.isEmpty()) {
                    continue;
                }
                if (!"xml".equals(prefix)) {
                    if (prefix != null && !prefix.isEmpty()) {
                        if (!prefixSet.contains(prefix)) {
                            prefixSet.add(prefix);
                            comparableNamespaceList.add(new ComparableNamespace(prefix, attributeNameNamespaceURI));
                        }
                        continue;
                    }
                }
                //add all attrs with xml - prefix (eg. xml:lang) to attr list:
                comparableAttributeList.add(new ComparableAttribute(attributeName, attribute.getValue()));
            }

            nsStack.push(comparableNamespaceList);
            attrStack.push(comparableAttributeList);

            return new XMLEventNS(xmlEvent, nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
        } else if (xmlEvent.isEndElement()) {
            nsStack.pop();
            attrStack.pop();
        }
        return xmlEvent;
    }

    //todo transformer factory?
    public static Transformer getTransformer(Object methodParameter1, Object methodParameter2, String algorithm)
            throws XMLSecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {

        Class<Transformer> transformerClass = (Class<Transformer>) TransformerAlgorithmMapper.getTransformerClass(algorithm, null);
        if (transformerClass == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM);
        }
        Transformer childTransformer = transformerClass.newInstance();
        if (methodParameter2 != null) {
            childTransformer.setList((List) methodParameter1);
            childTransformer.setOutputStream((OutputStream) methodParameter2);
        } else {
            childTransformer.setTransformer((Transformer) methodParameter1);
        }
        return childTransformer;
    }

    public static <T> T getType(List<Object> objects, Class<T> clazz) {
        for (int i = 0; i < objects.size(); i++) {
            Object o = objects.get(i);
            if (o instanceof JAXBElement) {
                o = ((JAXBElement) o).getValue();
            }
            if (clazz.isAssignableFrom(o.getClass())) {
                return (T) o;
            }
        }
        return null;
    }

    public static <T> T getQNameType(List<Object> objects, QName qName) {
        for (int i = 0; i < objects.size(); i++) {
            Object o = objects.get(i);
            if (o instanceof JAXBElement) {
                JAXBElement jaxbElement = (JAXBElement) o;
                if (jaxbElement.getName().equals(qName)) {
                    return (T) jaxbElement.getValue();
                }
            }
        }
        return null;
    }

    public static String getQNameAttribute(Map<QName, String> attributes, QName qName) {
        return attributes.get(qName);
    }
}
