/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package ch.gigerstyle.xmlsec.impl.transformer.canonicalizer;

import ch.gigerstyle.xmlsec.ext.ComparableAttribute;
import ch.gigerstyle.xmlsec.ext.ComparableNamespace;
import ch.gigerstyle.xmlsec.ext.Transformer;
import ch.gigerstyle.xmlsec.ext.XMLEventNS;

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
public class Canonicalizer20010315Transformer implements Transformer {

    private static final byte[] _END_PI = {'?', '>'};
    private static final byte[] _BEGIN_PI = {'<', '?'};
    private static final byte[] _END_COMM = {'-', '-', '>'};
    private static final byte[] _BEGIN_COMM = {'<', '!', '-', '-'};
    private static final byte[] __XA_ = {'&', '#', 'x', 'A', ';'};
    private static final byte[] __X9_ = {'&', '#', 'x', '9', ';'};
    private static final byte[] _QUOT_ = {'&', 'q', 'u', 'o', 't', ';'};
    private static final byte[] __XD_ = {'&', '#', 'x', 'D', ';'};
    private static final byte[] _GT_ = {'&', 'g', 't', ';'};
    private static final byte[] _LT_ = {'&', 'l', 't', ';'};
    private static final byte[] _END_TAG = {'<', '/'};
    private static final byte[] _AMP_ = {'&', 'a', 'm', 'p', ';'};
    final static byte[] equalsStr = {'=', '\"'};

    static final int NODE_BEFORE_DOCUMENT_ELEMENT = -1;
    static final int NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT = 0;
    static final int NODE_AFTER_DOCUMENT_ELEMENT = 1;

    private Map cache = new HashMap();

    private C14NStack outputStack = new C14NStack();

    private boolean includeComments = false;
    private boolean exclusive = false;
    private int documentLevel = NODE_BEFORE_DOCUMENT_ELEMENT;

    private QName rootElement = null;

    private boolean firstCall = true;
    //private List outPutted = new ArrayList();

    SortedSet inclusiveNamespaces = null;

    public Canonicalizer20010315Transformer(String inclusiveNamespaces, boolean includeComments, boolean exclusive) {
        this.includeComments = includeComments;
        this.exclusive = exclusive;
        this.inclusiveNamespaces = prefixStr2Set(inclusiveNamespaces);
    }

    public static SortedSet prefixStr2Set(String inclusiveNamespaces) {

        if ((inclusiveNamespaces == null) || (inclusiveNamespaces.length() == 0)) {
            return null;
        }

        SortedSet prefixes = new TreeSet();

        StringTokenizer st = new StringTokenizer(inclusiveNamespaces, " \t\r\n");

        while (st.hasMoreTokens()) {
            String prefix = st.nextToken();

            if (prefix.equals("#default")) {
                prefixes.add("");
            } else {
                prefixes.add(prefix);
            }
        }
        return prefixes;
    }

    public void transform(XMLEvent xmlEvent, OutputStream outputStream) throws XMLStreamException {
        try {
            switch (xmlEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:

                    StartElement startElement = xmlEvent.asStartElement();

                    if (documentLevel == NODE_BEFORE_DOCUMENT_ELEMENT) {
                        rootElement = startElement.getName();
                    }

                    documentLevel = NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT;

                    outputStack.push(new ArrayList());

                    outputStream.write('<');
                    String prefix = startElement.getName().getPrefix();
                    if (prefix != null && prefix.length() > 0) {
                        UtfHelpper.writeByte(prefix, outputStream, cache);
                        outputStream.write(':');
                    }
                    String name = startElement.getName().getLocalPart();
                    UtfHelpper.writeByte(name, outputStream, cache);

                    //todo check before cast
                    XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;

                    List<ComparableNamespace>[] namespaceList;
                    List<ComparableAttribute>[] xmlAttributeList;

                    SortedSet<ComparableNamespace> nsSet = new TreeSet<ComparableNamespace>();

                    if (!firstCall) {
                        //just current event is interesting
                        namespaceList = new List[]{xmlEventNS.getNamespaceList()[0]};
                        xmlAttributeList = new List[]{xmlEventNS.getAttributeList()[0]};
                    } else {
                        outputStack.peek().add(new ComparableNamespace(""));
                        if (exclusive) {
                            namespaceList = new List[]{xmlEventNS.getNamespaceList()[0]};
                            xmlAttributeList = new List[]{xmlEventNS.getAttributeList()[0]};
                            /*
                            for (int i = 0; i < namespaceList.length; i++) {
                                List<ComparableNamespace> comparableNamespaceList = namespaceList[i];
                                for (int j = 0; j < comparableNamespaceList.size(); j++) {
                                    ComparableNamespace comparableNamespace = comparableNamespaceList.get(j);
                                    System.out.println("Namespace first element: " + comparableNamespace.getPrefix() + ":" + comparableNamespace.getNamespaceURI());
                                }
                            }
                            System.out.println("End Namespaces");
                              */
                            //all previous events are interesting:
                        } else {
                            namespaceList = xmlEventNS.getNamespaceList();
                            xmlAttributeList = xmlEventNS.getAttributeList();

                            //add all defined namespaces up to current element to the outputted
                            for (int i = 1; i < xmlEventNS.getNamespaceList().length; i++) {
                                List<ComparableNamespace> comparableNamespaces = xmlEventNS.getNamespaceList()[i];
                                for (int j = 0; j < comparableNamespaces.size(); j++) {
                                    ComparableNamespace comparableNamespace = comparableNamespaces.get(j);

                                    //look for redefinition of prefix
                                    //todo if can be removed now?:
                                    if (comparableNamespace.getPrefix().equals(startElement.getName().getPrefix())
                                            && !comparableNamespace.getNamespaceURI().equals(startElement.getName().getNamespaceURI())) {
                                        continue;
                                    }

                                    final ComparableNamespace found = (ComparableNamespace) outputStack.containsOnStack(comparableNamespace);
                                    if (found != null && comparableNamespace.getNamespaceURI().equals(found.getNamespaceURI())) {
                                        continue;
                                    }

                                    if (this.inclusiveNamespaces != null) {
                                        if (this.inclusiveNamespaces.contains(comparableNamespace.getPrefix())) {
                                            outputStack.peek().add(comparableNamespace);
                                            nsSet.add(comparableNamespace);
                                        }
                                    } else {
                                        nsSet.add(comparableNamespace);
                                        outputStack.peek().add(comparableNamespace);
                                    }
                                }
                            }

                        }
                        firstCall = false;
                    }

                    for (int i = 0; i < namespaceList.length; i++) {
                        List<ComparableNamespace> comparableNamespaces = namespaceList[i];
                        for (int j = 0; j < comparableNamespaces.size(); j++) {
                            ComparableNamespace comparableNamespace = comparableNamespaces.get(j);

                            final ComparableNamespace found = (ComparableNamespace) outputStack.containsOnStack(comparableNamespace);
                            /*
                            if ((found != null && found.isDefaultNamespaceDeclaration() == false)
                                    || (found != null && found.isDefaultNamespaceDeclaration() && found.getNamespaceURI().equals(comparableNamespace.getNamespaceURI()))) {
                                continue;
                            }
                            */
                            //found means the prefix matched. so check the ns further
                            //todo the same with attributes??
                            if (found != null && comparableNamespace.getNamespaceURI().equals(found.getNamespaceURI())) {
                                continue;
                            } /*else if (comparableNamespace.getNamespaceURI().equals("")) {
                                outputStack.peek().add(comparableNamespace);
                                continue;
                            }*/
                            if (exclusive) {
                                //lookup ns is used (visible utilized?) in current element or in its attributes...
                                boolean nsUsedByAttr = false;
                                Iterator<Attribute> attrIterator = startElement.getAttributes();
                                while (attrIterator.hasNext()) {
                                    Attribute attribute = attrIterator.next();
                                    if (comparableNamespace.getNamespaceURI().equals(attribute.getName().getNamespaceURI())) {
                                        nsUsedByAttr = true;
                                        break;
                                    }
                                }
                                if (!nsUsedByAttr
                                        //&& !comparableNamespace.getNamespaceURI().equals(startElement.getName().getNamespaceURI())
                                        && !comparableNamespace.getPrefix().equals(startElement.getName().getPrefix())) {
                                    continue;
                                }
                            }

                            if (this.inclusiveNamespaces != null) {
                                if (this.inclusiveNamespaces.contains(comparableNamespace.getPrefix())) {
                                    nsSet.add(comparableNamespace);
                                }
                            } else {
                                nsSet.add(comparableNamespace);
                            }
                            outputStack.peek().add(comparableNamespace);
                        }
                    }

                    Iterator<ComparableNamespace> namespaceIterator = nsSet.iterator();
                    while (namespaceIterator.hasNext()) {
                        ComparableNamespace namespace = namespaceIterator.next();

                        if (!namespaceIsAbsolute(namespace.getNamespaceURI())) {
                            throw new XMLStreamException("namespace is relative encountered");
                        }

/*                        if (!startElement.getName().getPrefix().equals("") && namespace.isDefaultNamespaceDeclaration()) {
                            continue;
                        }
*/
                        if (namespace.isDefaultNamespaceDeclaration()) {
                            outputAttrToWriter("xmlns", namespace.getNamespaceURI(), outputStream, cache);
                        } else {
                            outputAttrToWriter("xmlns:" + namespace.getPrefix(), namespace.getNamespaceURI(), outputStream, cache);
                        }
                    }


                    SortedSet<ComparableAttribute> attrSet = new TreeSet<ComparableAttribute>();
                    for (int i = 0; i < xmlAttributeList.length; i++) {
                        List<ComparableAttribute> comparableAttributes = xmlAttributeList[i];
                        for (int j = 0; j < comparableAttributes.size(); j++) {
                            ComparableAttribute comparableAttribute = comparableAttributes.get(j);
                            if (outputStack.containsOnStack(comparableAttribute) != null) {
                                continue;
                            }
                            //System.out.println("Attr: " + comparableAttribute.getName() + " " + comparableAttribute.getValue());
                            attrSet.add(comparableAttribute);
                            //outPutted.add(comparableAttribute);
                            outputStack.peek().add(comparableAttribute);
                        }
                    }
                    Iterator<Attribute> attributesIterator = startElement.getAttributes();
                    while (attributesIterator.hasNext()) {
                        Attribute attribute = attributesIterator.next();
                        if ("xml".equals(attribute.getName().getPrefix())) {
                            continue;
                        }

                        attrSet.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
                    }

                    Iterator<ComparableAttribute> attributeIterator = attrSet.iterator();
                    while (attributeIterator.hasNext()) {
                        ComparableAttribute attribute = attributeIterator.next();

                        //outputAttrToWriter(attribute.getName().getPrefix() + ":" + attribute.getName().getLocalPart(), attribute.getValue(), outputStream, cache);

                        String localPart = "";
                        if (attribute.getName().getPrefix() != null && attribute.getName().getPrefix().length() > 0) {
                            localPart += attribute.getName().getPrefix() + ":";
                        }
                        localPart += attribute.getName().getLocalPart();
                        outputAttrToWriter(localPart,
                                attribute.getValue(),
                                outputStream, cache);
                    }

                    /*
                    Iterator<Attribute> attributesIterator = startElement.getAttributes();
                    while (attributesIterator.hasNext()) {
                        Attribute attribute = attributesIterator.next();
                        if ("xml".equals(attribute.getName().getPrefix())) {
                            continue;
                        }

                        String localPart = "";
                        if (attribute.getName().getPrefix() != null && attribute.getName().getPrefix().length() > 0) {
                            localPart += attribute.getName().getPrefix() + ":";
                        }
                        localPart += attribute.getName().getLocalPart();
                        outputAttrToWriter(localPart,
                                attribute.getValue(),
                                outputStream, cache);
                    }
                      */
                    outputStream.write('>');
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    EndElement endElement = xmlEvent.asEndElement();
                    String localName = endElement.getName().getLocalPart();
                    String localPrefix = endElement.getName().getPrefix();
                    outputStream.write(_END_TAG);
                    if (localPrefix != null && localPrefix.length() > 0) {
                        UtfHelpper.writeByte(localPrefix, outputStream, cache);
                        outputStream.write(':');
                    }
                    UtfHelpper.writeStringToUtf8(localName, outputStream);
                    outputStream.write('>');

                    //We fineshed with this level, pop to the previous definitions.
                    //                    ns.outputNodePop();

                    //hashMapStack.pop();
                    outputStack.pop();
                    //todo the size() test is probably enough 
                    if (outputStack.size() == 0 && endElement.getName().equals(rootElement)) {
                        documentLevel = NODE_AFTER_DOCUMENT_ELEMENT;
                    }

                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    xmlEventNS = (XMLEventNS) xmlEvent;
                    outputPItoWriter(((ProcessingInstruction) xmlEventNS.getCurrentEvent()), outputStream, documentLevel);
                    break;
                case XMLStreamConstants.CHARACTERS:
                    if (documentLevel == NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlEvent.asCharacters().getData(), outputStream);
                    }
                    break;
                case XMLStreamConstants.COMMENT:
                    if (includeComments) {
                        xmlEventNS = (XMLEventNS) xmlEvent;
                        outputCommentToWriter(((Comment) xmlEventNS.getCurrentEvent()), outputStream, documentLevel);
                    }
                    break;
                case XMLStreamConstants.SPACE:
                    if (documentLevel == NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlEvent.asCharacters().getData(), outputStream);
                    }
                    break;
                case XMLStreamConstants.START_DOCUMENT:
                    documentLevel = NODE_BEFORE_DOCUMENT_ELEMENT;
                    //                    ns.outputNodePush();
                    break;
                case XMLStreamConstants.END_DOCUMENT:
                    break;
                //todo exceptions:
                case XMLStreamConstants.ENTITY_REFERENCE:
                    throw new XMLStreamException("empty");
                case XMLStreamConstants.ATTRIBUTE:
                    break;
                case XMLStreamConstants.DTD:
                    //throw new XMLStreamException("empty");
                    break;
                case XMLStreamConstants.CDATA:
                    outputTextToWriter(xmlEvent.asCharacters().getData(), outputStream);
                    break;
                case XMLStreamConstants.NAMESPACE:
                    break;
                //todo exceptions:
                case XMLStreamConstants.NOTATION_DECLARATION:
                    throw new XMLStreamException("empty");
                case XMLStreamConstants.ENTITY_DECLARATION:
                    throw new XMLStreamException("empty");
            }
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }

    private static final void outputAttrToWriter(final String name, final String value, final OutputStream writer,
                                                 final Map cache) throws IOException {
        writer.write(' ');
        UtfHelpper.writeByte(name, writer, cache);
        writer.write(equalsStr);
        byte[] toWrite;
        final int length = value.length();
        int i = 0;
        while (i < length) {
            char c = value.charAt(i++);

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
    static final void outputTextToWriter(final String text, final OutputStream writer) throws IOException {
        final int length = text.length();
        byte[] toWrite;
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);

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
    static final void outputPItoWriter(ProcessingInstruction currentPI, OutputStream writer, int position) throws IOException {

        if (position == NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write('\n');
        }
        writer.write(_BEGIN_PI);

        final String target = currentPI.getTarget();
        int length = target.length();

        for (int i = 0; i < length; i++) {
            char c = target.charAt(i);
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
        if (position == NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write('\n');
        }
    }

    /**
     * Method outputCommentToWriter
     *
     * @param currentComment
     * @param writer         writer where to write the things
     * @throws IOException
     */
    static final void outputCommentToWriter(Comment currentComment, OutputStream writer, int position) throws IOException {
        if (position == NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write('\n');
        }
        writer.write(_BEGIN_COMM);

        final String data = currentComment.getText();
        final int length = data.length();

        for (int i = 0; i < length; i++) {
            char c = data.charAt(i);
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
        if (position == NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write('\n');
        }
    }

    private boolean namespaceIsAbsolute(String namespaceValue) {

        // assume empty namespaces are absolute
        if (namespaceValue.length() == 0) {
            return true;
        }
        return namespaceValue.indexOf(':') > 0;
    }


    public static class C14NStack extends ArrayDeque<List> {

        public Object containsOnStack(Object o) {
            if (o == null) {
                return null;
            }
            //Important: iteration order from head to tail!
            Iterator<List> elementInterator = super.iterator();
            while (elementInterator.hasNext()) {
                List list = elementInterator.next();
                if (list.contains(o)) {
                    return list.get(list.indexOf(o));
                }
            }
            return null;
        }
    }
}
