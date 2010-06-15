package ch.gigerstyle.xmlsec;

import org.xml.sax.*;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.AttributesImpl;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.sax.SAXSource;

/**
 * User: giger
 * Date: May 28, 2010
 * Time: 6:06:10 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class StaxSource extends SAXSource implements XMLReader {

    private XMLStreamReader streamReader;

    private ContentHandler contentHandler;

    private LexicalHandler lexicalHandler;

    public StaxSource(XMLStreamReader streamReader) {
        this.streamReader = streamReader;
        setInputSource(new InputSource());
    }

    public XMLReader getXMLReader() {
        return this;
    }

    public XMLStreamReader getXMLStreamReader() {
        return streamReader;
    }

    protected void parse() throws SAXException {
        try {
            while (true) {
                switch (streamReader.getEventType()) {
                // Attributes are handled in START_ELEMENT
                case XMLStreamConstants.ATTRIBUTE:
                    break;
                case XMLStreamConstants.CDATA:
                {
                    if (lexicalHandler != null) {
                        lexicalHandler.startCDATA();
                    }
                    int length = streamReader.getTextLength();
                    int start = streamReader.getTextStart();
                    char[] chars = streamReader.getTextCharacters();
                    contentHandler.characters(chars, start, length);
                    if (lexicalHandler != null) {
                        lexicalHandler.endCDATA();
                    }
                    break;
                }
                case XMLStreamConstants.CHARACTERS:
                {
                    int length = streamReader.getTextLength();
                    int start = streamReader.getTextStart();
                    char[] chars = streamReader.getTextCharacters();
                    contentHandler.characters(chars, start, length);
                    break;
                }
                case XMLStreamConstants.SPACE:
                {
                    int length = streamReader.getTextLength();
                    int start = streamReader.getTextStart();
                    char[] chars = streamReader.getTextCharacters();
                    contentHandler.ignorableWhitespace(chars, start, length);
                    break;
                }
                case XMLStreamConstants.COMMENT:
                    if (lexicalHandler != null) {
                        int length = streamReader.getTextLength();
                        int start = streamReader.getTextStart();
                        char[] chars = streamReader.getTextCharacters();
                        lexicalHandler.comment(chars, start, length);
                    }
                    break;
                case XMLStreamConstants.DTD:
                    break;
                case XMLStreamConstants.END_DOCUMENT:
                    contentHandler.endDocument();
                    return;
                case XMLStreamConstants.END_ELEMENT: {
                    String uri = streamReader.getNamespaceURI();
                    String localName = streamReader.getLocalName();
                    String prefix = streamReader.getPrefix();
                    String qname = prefix != null && prefix.length() > 0
                        ? prefix + ":" + localName : localName;
                    contentHandler.endElement(uri, localName, qname);
                    break;
                }
                case XMLStreamConstants.ENTITY_DECLARATION:
                case XMLStreamConstants.ENTITY_REFERENCE:
                case XMLStreamConstants.NAMESPACE:
                case XMLStreamConstants.NOTATION_DECLARATION:
                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    break;
                case XMLStreamConstants.START_DOCUMENT:
                    contentHandler.startDocument();
                    break;
                case XMLStreamConstants.START_ELEMENT: {
                    String uri = streamReader.getNamespaceURI();
                    String localName = streamReader.getLocalName();
                    String prefix = streamReader.getPrefix();
                    String qname = prefix != null && prefix.length() > 0
                        ? prefix + ":" + localName : localName;
                    contentHandler.startElement(uri == null ? "" : uri, localName, qname, getAttributes());
                    break;
                }
                default:
                    break;
                }
                if (!streamReader.hasNext()) {
                    return;
                }
                streamReader.next();
            }
        } catch (XMLStreamException e) {
            SAXParseException spe;
            if (e.getLocation() != null) {
                spe = new SAXParseException(e.getMessage(), null, null,
                                            e.getLocation().getLineNumber(),
                                            e.getLocation().getColumnNumber(), e);
            } else {
                spe = new SAXParseException(e.getMessage(), null, null, -1, -1, e);
            }
            spe.initCause(e);
            throw spe;
        }
    }

    protected String getQualifiedName() {
        String prefix = streamReader.getPrefix();
        if (prefix != null && prefix.length() > 0) {
            return prefix + ":" + streamReader.getLocalName();
        } else {
            return streamReader.getLocalName();
        }
    }

    protected Attributes getAttributes() {
        AttributesImpl attrs = new AttributesImpl();
        // Adding namespace declaration as attributes is necessary because
        // the xalan implementation that ships with SUN JDK 1.4 is bugged
        // and does not handle the startPrefixMapping method
        for (int i = 0; i < streamReader.getNamespaceCount(); i++) {
            String prefix = streamReader.getNamespacePrefix(i);
            String uri = streamReader.getNamespaceURI(i);
            if (uri == null) {
                uri = "";
            }
            // Default namespace
            if (prefix == null || prefix.length() == 0) {
                attrs.addAttribute(XMLConstants.DEFAULT_NS_PREFIX,
                                   null,
                                   XMLConstants.XMLNS_ATTRIBUTE,
                                   "CDATA",
                                   uri);
            } else {
                attrs.addAttribute(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
                                   prefix,
                                   XMLConstants.XMLNS_ATTRIBUTE + ":" + prefix,
                                   "CDATA",
                                   uri);
            }
        }
        for (int i = 0; i < streamReader.getAttributeCount(); i++) {
            String uri = streamReader.getAttributeNamespace(i);
            String localName = streamReader.getAttributeLocalName(i);
            String prefix = streamReader.getAttributePrefix(i);
            String qName;
            if (prefix != null && prefix.length() > 0) {
                qName = prefix + ':' + localName;
            } else {
                qName = localName;
            }
            String type = streamReader.getAttributeType(i);
            String value = streamReader.getAttributeValue(i);
            if (value == null) {
                value = "";
            }

            attrs.addAttribute(uri == null ? "" : uri, localName, qName, type, value);
        }
        return attrs;
    }

    public boolean getFeature(String name) throws SAXNotRecognizedException, SAXNotSupportedException {
        return false;
    }

    public void setFeature(String name, boolean value)
        throws SAXNotRecognizedException, SAXNotSupportedException {
    }

    public Object getProperty(String name) throws SAXNotRecognizedException, SAXNotSupportedException {
        return null;
    }

    public void setProperty(String name, Object value)
        throws SAXNotRecognizedException, SAXNotSupportedException {
        if ("http://xml.org/sax/properties/lexical-handler".equals(name)) {
            lexicalHandler = (LexicalHandler) value;
        } else {
            throw new SAXNotRecognizedException(name);
        }
    }

    public void setEntityResolver(EntityResolver resolver) {
    }

    public EntityResolver getEntityResolver() {
        return null;
    }

    public void setDTDHandler(DTDHandler handler) {
    }

    public DTDHandler getDTDHandler() {
        return null;
    }

    public void setContentHandler(ContentHandler handler) {
        this.contentHandler = handler;
    }

    public ContentHandler getContentHandler() {
        return this.contentHandler;
    }

    public void setErrorHandler(ErrorHandler handler) {
    }

    public ErrorHandler getErrorHandler() {
        return null;
    }

    public void parse(InputSource input) throws SAXException {
        StaxSource.this.parse();
    }

    public void parse(String systemId) throws SAXException {
        StaxSource.this.parse();
    }

}
