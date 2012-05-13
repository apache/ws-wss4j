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
package org.swssf.xmlsec.impl.transformer.canonicalizer;

import org.swssf.xmlsec.ext.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class CanonicalizerBase implements Transformer {

    protected static final byte[] _END_PI = {'?', '>'};
    protected static final byte[] _BEGIN_PI = {'<', '?'};
    protected static final byte[] _END_COMM = {'-', '-', '>'};
    protected static final byte[] _BEGIN_COMM = {'<', '!', '-', '-'};
    protected static final byte[] __XA_ = {'&', '#', 'x', 'A', ';'};
    protected static final byte[] __X9_ = {'&', '#', 'x', '9', ';'};
    protected static final byte[] _QUOT_ = {'&', 'q', 'u', 'o', 't', ';'};
    protected static final byte[] __XD_ = {'&', '#', 'x', 'D', ';'};
    protected static final byte[] _GT_ = {'&', 'g', 't', ';'};
    protected static final byte[] _LT_ = {'&', 'l', 't', ';'};
    protected static final byte[] _END_TAG = {'<', '/'};
    protected static final byte[] _AMP_ = {'&', 'a', 'm', 'p', ';'};
    protected static final byte[] EQUAL_STRING = {'=', '\"'};
    protected static final byte[] NEWLINE = {'\n'};

    protected static final String XML = "xml";
    protected static final String XMLNS = "xmlns";
    protected static final char DOUBLEPOINT = ':';
    protected static final String XMLNS_DOUBLEPOINT = XMLNS + DOUBLEPOINT;

    private enum DocumentLevel {
        NODE_BEFORE_DOCUMENT_ELEMENT,
        NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT,
        NODE_AFTER_DOCUMENT_ELEMENT
    }

    private OutputStream outputStream;

    private static final Map<String, byte[]> cache = new WeakHashMap<String, byte[]>();
    private C14NStack<List<Comparable>> outputStack = new C14NStack<List<Comparable>>();
    private boolean includeComments = false;
    private DocumentLevel currentDocumentLevel = DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT;
    private boolean firstCall = true;
    private SortedSet<String> inclusiveNamespaces = null;

    public CanonicalizerBase(boolean includeComments) {
        this.includeComments = includeComments;
    }

    @Override
    public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
        this.outputStream = outputStream;
    }

    @Override
    public void setList(List list) throws XMLSecurityException {
        this.inclusiveNamespaces = prefixList2Set(list);
    }

    @Override
    public void setTransformer(Transformer transformer) throws XMLSecurityException {
        throw new UnsupportedOperationException("Transformer not supported");
    }

    public static SortedSet<String> prefixList2Set(List<String> inclusiveNamespaces) {

        if ((inclusiveNamespaces == null) || (inclusiveNamespaces.size() == 0)) {
            return null;
        }

        final SortedSet<String> prefixes = new TreeSet<String>();

        for (int i = 0; i < inclusiveNamespaces.size(); i++) {
            final String s = inclusiveNamespaces.get(i).intern();
            if ("#default".equals(s)) {
                prefixes.add("");
            } else {
                prefixes.add(s);
            }
        }
        return prefixes;
    }

    protected void getCurrentUtilizedNamespaces(final XMLEventNS xmlEventNS, final SortedSet<ComparableNamespace> utilizedNamespaces,
                                                final C14NStack<List<Comparable>> outputStack) {
        final List<ComparableNamespace> currentUtilizedNamespace = xmlEventNS.getNamespaceList()[0];
        for (int j = 0; j < currentUtilizedNamespace.size(); j++) {
            final ComparableNamespace comparableNamespace = currentUtilizedNamespace.get(j);

            final ComparableNamespace found = (ComparableNamespace) outputStack.containsOnStack(comparableNamespace);
            //found means the prefix matched. so check the ns further
            if (found != null && found.getNamespaceURI() != null && found.getNamespaceURI().equals(comparableNamespace.getNamespaceURI())) {
                continue;
            }

            utilizedNamespaces.add(comparableNamespace);
            outputStack.peek().add(comparableNamespace);
        }
    }

    protected void getCurrentUtilizedAttributes(final XMLEventNS xmlEventNS, final SortedSet<ComparableAttribute> utilizedAttributes,
                                                final C14NStack<List<Comparable>> outputStack) {
        final StartElement startElement = xmlEventNS.asStartElement();
        @SuppressWarnings("unchecked")
        final Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            final Attribute attribute = attributesIterator.next();
            utilizedAttributes.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
        }
    }

    protected void getInitialUtilizedNamespaces(final XMLEventNS xmlEventNS, final SortedSet<ComparableNamespace> utilizedNamespaces,
                                                final C14NStack<List<Comparable>> outputStack) {
        final List<ComparableNamespace>[] visibleNamespaceList = xmlEventNS.getNamespaceList();
        for (int i = 0; i < visibleNamespaceList.length; i++) {
            final List<ComparableNamespace> initialUtilizedNamespace = visibleNamespaceList[i];
            for (int j = 0; j < initialUtilizedNamespace.size(); j++) {
                final ComparableNamespace comparableNamespace = initialUtilizedNamespace.get(j);

                final ComparableNamespace found = (ComparableNamespace) outputStack.containsOnStack(comparableNamespace);
                //found means the prefix matched. so check the ns further
                if (found != null && found.getNamespaceURI() != null && found.getNamespaceURI().equals(comparableNamespace.getNamespaceURI())) {
                    continue;
                }

                utilizedNamespaces.add(comparableNamespace);
                outputStack.peek().add(comparableNamespace);
            }
        }
    }

    protected void getInitialUtilizedAttributes(final XMLEventNS xmlEventNS, final SortedSet<ComparableAttribute> utilizedAttributes,
                                                final C14NStack<List<Comparable>> outputStack) {
        final List<ComparableAttribute>[] visibleAttributeList = xmlEventNS.getAttributeList();
        for (int i = 0; i < visibleAttributeList.length; i++) {
            final List<ComparableAttribute> comparableAttributes = visibleAttributeList[i];
            for (int j = 0; j < comparableAttributes.size(); j++) {
                final ComparableAttribute comparableAttribute = comparableAttributes.get(j);
                if (outputStack.containsOnStack(comparableAttribute) != null) {
                    continue;
                }
                utilizedAttributes.add(comparableAttribute);
                outputStack.peek().add(comparableAttribute);
            }
        }
        final StartElement startElement = xmlEventNS.asStartElement();
        @SuppressWarnings("unchecked")
        final Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            final Attribute attribute = attributesIterator.next();
            //attributes with xml prefix are already processed in the for loop above
            if (XML.equals(attribute.getName().getPrefix())) {
                continue;
            }

            utilizedAttributes.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
        }
    }

    public void transform(final XMLEvent xmlEvent) throws XMLStreamException {
        try {
            switch (xmlEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:

                    final StartElement startElement = xmlEvent.asStartElement();

                    currentDocumentLevel = DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT;
                    outputStack.push(Collections.<Comparable>emptyList());

                    final XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;

                    final SortedSet<ComparableNamespace> utilizedNamespaces = new TreeSet<ComparableNamespace>();
                    final SortedSet<ComparableAttribute> utilizedAttributes = new TreeSet<ComparableAttribute>();

                    if (firstCall) {
                        outputStack.peek().add(new ComparableNamespace(""));
                        outputStack.push(Collections.<Comparable>emptyList());
                        firstCall = false;

                        if (this.inclusiveNamespaces != null) {
                            final Iterator<String> iterator = this.inclusiveNamespaces.iterator();
                            while (iterator.hasNext()) {
                                final String next = iterator.next();
                                final String ns = startElement.getNamespaceURI(next);
                                //add default ns:
                                if (ns == null && next != null && next.isEmpty()) {
                                    final ComparableNamespace comparableNamespace = new ComparableNamespace(next, "");
                                    utilizedNamespaces.add(comparableNamespace);
                                    outputStack.peek().add(comparableNamespace);
                                } else if (ns != null) {
                                    final ComparableNamespace comparableNamespace = new ComparableNamespace(next, ns);
                                    utilizedNamespaces.add(comparableNamespace);
                                    outputStack.peek().add(comparableNamespace);
                                }
                            }
                        }

                        getInitialUtilizedNamespaces(xmlEventNS, utilizedNamespaces, outputStack);
                        getInitialUtilizedAttributes(xmlEventNS, utilizedAttributes, outputStack);
                    } else {
                        getCurrentUtilizedNamespaces(xmlEventNS, utilizedNamespaces, outputStack);
                        getCurrentUtilizedAttributes(xmlEventNS, utilizedAttributes, outputStack);
                    }

                    outputStream.write('<');
                    final String prefix = startElement.getName().getPrefix();
                    if (prefix != null && !prefix.isEmpty()) {
                        UtfHelpper.writeByte(prefix, outputStream, cache);
                        outputStream.write(DOUBLEPOINT);
                    }
                    final String name = startElement.getName().getLocalPart();
                    UtfHelpper.writeByte(name, outputStream, cache);

                    final Iterator<ComparableNamespace> namespaceIterator = utilizedNamespaces.iterator();
                    while (namespaceIterator.hasNext()) {
                        final ComparableNamespace namespace = namespaceIterator.next();

                        if (!namespaceIsAbsolute(namespace.getNamespaceURI())) {
                            throw new XMLStreamException("namespace is relative encountered: " + namespace.getNamespaceURI());
                        }

                        if (namespace.isDefaultNamespaceDeclaration()) {
                            outputAttrToWriter(XMLNS, namespace.getNamespaceURI(), outputStream, cache);
                        } else {
                            outputAttrToWriter(XMLNS_DOUBLEPOINT + namespace.getPrefix(), namespace.getNamespaceURI(), outputStream, cache);
                        }
                    }

                    final Iterator<ComparableAttribute> attributeIterator = utilizedAttributes.iterator();
                    while (attributeIterator.hasNext()) {
                        final ComparableAttribute attribute = attributeIterator.next();

                        final QName attributeName = attribute.getName();
                        if (attributeName.getPrefix() != null && !attributeName.getPrefix().isEmpty()) {
                            final String localPart = attributeName.getPrefix() + DOUBLEPOINT + attributeName.getLocalPart();
                            outputAttrToWriter(localPart, attribute.getValue(), outputStream, cache);
                        } else {
                            outputAttrToWriter(attributeName.getLocalPart(), attribute.getValue(), outputStream, cache);
                        }
                    }

                    outputStream.write('>');
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    final EndElement endElement = xmlEvent.asEndElement();
                    final String localPrefix = endElement.getName().getPrefix();
                    outputStream.write(_END_TAG);
                    if (localPrefix != null && !localPrefix.isEmpty()) {
                        UtfHelpper.writeByte(localPrefix, outputStream, cache);
                        outputStream.write(DOUBLEPOINT);
                    }
                    UtfHelpper.writeStringToUtf8(endElement.getName().getLocalPart(), outputStream);
                    outputStream.write('>');

                    //We finished with this level, pop to the previous definitions.
                    outputStack.pop();
                    if (outputStack.size() == 1) {
                        currentDocumentLevel = DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT;
                    }

                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    outputPItoWriter(((ProcessingInstruction) xmlEvent), this.outputStream, currentDocumentLevel);
                    break;
                case XMLStreamConstants.CHARACTERS:
                    if (currentDocumentLevel == DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlEvent.asCharacters().getData(), this.outputStream);
                    }
                    break;
                case XMLStreamConstants.COMMENT:
                    if (includeComments) {
                        outputCommentToWriter(((Comment) xmlEvent), this.outputStream, currentDocumentLevel);
                    }
                    break;
                case XMLStreamConstants.SPACE:
                    if (currentDocumentLevel == DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlEvent.asCharacters().getData(), this.outputStream);
                    }
                    break;
                case XMLStreamConstants.START_DOCUMENT:
                    currentDocumentLevel = DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT;
                    break;
                case XMLStreamConstants.END_DOCUMENT:
                    break;
                case XMLStreamConstants.ENTITY_REFERENCE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlEvent));
                case XMLStreamConstants.ATTRIBUTE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlEvent));
                case XMLStreamConstants.DTD:
                    break;
                case XMLStreamConstants.CDATA:
                    outputTextToWriter(xmlEvent.asCharacters().getData(), this.outputStream);
                    break;
                case XMLStreamConstants.NAMESPACE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlEvent));
                case XMLStreamConstants.NOTATION_DECLARATION:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlEvent));
                case XMLStreamConstants.ENTITY_DECLARATION:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlEvent));
            }
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }

    protected static void outputAttrToWriter(final String name, final String value, final OutputStream writer,
                                             final Map<String, byte[]> cache) throws IOException {
        writer.write(' ');
        UtfHelpper.writeByte(name, writer, cache);
        writer.write(EQUAL_STRING);
        byte[] toWrite;
        final int length = value.length();
        int i = 0;
        while (i < length) {
            final char c = value.charAt(i++);

            switch (c) {

                case '&':
                    toWrite = _AMP_;
                    break;

                case '<':
                    toWrite = _LT_;
                    break;

                case '"':
                    toWrite = _QUOT_;
                    break;

                case 0x09:    // '\t'
                    toWrite = __X9_;
                    break;

                case 0x0A:    // '\n'
                    toWrite = __XA_;
                    break;

                case 0x0D:    // '\r'
                    toWrite = __XD_;
                    break;

                default:
                    if (c < 0x80) {
                        writer.write(c);
                    } else {
                        UtfHelpper.writeCharToUtf8(c, writer);
                    }
                    continue;
            }
            writer.write(toWrite);
        }

        writer.write('\"');
    }

    /**
     * Outputs a Text of CDATA section to the internal Writer.
     *
     * @param text
     * @param writer writer where to write the things
     * @throws IOException
     */
    protected static void outputTextToWriter(final String text, final OutputStream writer) throws IOException {
        final int length = text.length();
        byte[] toWrite;
        for (int i = 0; i < length; i++) {
            final char c = text.charAt(i);

            switch (c) {

                case '&':
                    toWrite = _AMP_;
                    break;

                case '<':
                    toWrite = _LT_;
                    break;

                case '>':
                    toWrite = _GT_;
                    break;

                case 0xD:
                    toWrite = __XD_;
                    break;

                default:
                    if (c < 0x80) {
                        writer.write(c);
                    } else {
                        UtfHelpper.writeCharToUtf8(c, writer);
                    }
                    continue;
            }
            writer.write(toWrite);
        }
    }

    /**
     * Outputs a PI to the internal Writer.
     *
     * @param currentPI
     * @param writer    where to write the things
     * @throws IOException
     */
    protected static void outputPItoWriter(ProcessingInstruction currentPI, OutputStream writer, DocumentLevel position) throws IOException {
        if (position == DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
        writer.write(_BEGIN_PI);

        final String target = currentPI.getTarget();
        int length = target.length();

        for (int i = 0; i < length; i++) {
            final char c = target.charAt(i);
            if (c == 0x0D) {
                writer.write(__XD_);
            } else {
                if (c < 0x80) {
                    writer.write(c);
                } else {
                    UtfHelpper.writeCharToUtf8(c, writer);
                }
            }
        }

        final String data = currentPI.getData();

        length = data.length();

        if (length > 0) {
            writer.write(' ');

            for (int i = 0; i < length; i++) {
                char c = data.charAt(i);
                if (c == 0x0D) {
                    writer.write(__XD_);
                } else {
                    UtfHelpper.writeCharToUtf8(c, writer);
                }
            }
        }

        writer.write(_END_PI);
        if (position == DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
    }

    /**
     * Method outputCommentToWriter
     *
     * @param currentComment
     * @param writer         writer where to write the things
     * @throws IOException
     */
    protected static void outputCommentToWriter(Comment currentComment, OutputStream writer, DocumentLevel position) throws IOException {
        if (position == DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
        writer.write(_BEGIN_COMM);

        final String data = currentComment.getText();
        final int length = data.length();

        for (int i = 0; i < length; i++) {
            final char c = data.charAt(i);
            if (c == 0x0D) {
                writer.write(__XD_);
            } else {
                if (c < 0x80) {
                    writer.write(c);
                } else {
                    UtfHelpper.writeCharToUtf8(c, writer);
                }
            }
        }

        writer.write(_END_COMM);
        if (position == DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
    }

    private boolean namespaceIsAbsolute(final String namespaceValue) {
        // assume empty namespaces are absolute
        if (namespaceValue.isEmpty()) {
            return true;
        }
        return namespaceValue.indexOf(DOUBLEPOINT) > 0;
    }


    public static class C14NStack<E> extends ArrayDeque<List<Comparable>> {

        public Object containsOnStack(final Object o) {
            //Important: iteration order from head to tail!
            final Iterator<List<Comparable>> elementIterator = super.iterator();
            while (elementIterator.hasNext()) {
                final List list = elementIterator.next();
                if (list.size() == 0) {
                    continue;
                }
                final int idx = list.indexOf(o);
                if (idx != -1) {
                    return list.get(idx);
                }
            }
            return null;
        }

        @Override
        public List<Comparable> peek() {
            List<Comparable> list = super.peekFirst();
            if (list == Collections.<Comparable>emptyList()) {
                super.removeFirst();
                list = new ArrayList<Comparable>();
                super.addFirst(list);
            }
            return list;
        }

        @Override
        public List<Comparable> peekFirst() {
            throw new UnsupportedOperationException("Use peek()");
        }
    }
}
