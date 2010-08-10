package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.UncheckedXMLSecurityException;
import ch.gigerstyle.xmlsec.ext.XMLSecurityException;
import com.ctc.wstx.cfg.ErrorConsts;

import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.*;
import java.io.IOException;
import java.util.Iterator;

/**
 * User: giger
 * Date: May 27, 2010
 * Time: 6:55:43 PM
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
public class PipedXMLStreamReader implements XMLStreamReader, Thread.UncaughtExceptionHandler {

    private Throwable thrownExceptionByWriter = null;

    volatile boolean closedByWriter = false;
    volatile boolean closedByReader = false;
    boolean connected = false;

    /* REMIND: identification of the read and write sides needs to be
       more sophisticated.  Either using thread groups (but what about
       pipes within a thread?) or using finalization (but it may be a
       long time until the next GC). */
    Thread readSide;
    Thread writeSide;

    private static final int DEFAULT_PIPE_SIZE = 100;

    /**
     * The default size of the pipe's circular input buffer.
     */
    // This used to be a constant before the pipe size was allowed
    // to change. This field will continue to be maintained
    // for backward compatibility.
    protected static final int PIPE_SIZE = DEFAULT_PIPE_SIZE;

    /**
     * The circular buffer into which incoming data is placed.
     */
    protected XMLEvent buffer[];

    /**
     * The index of the position in the circular buffer at which the
     * next byte of data will be stored when received from the connected
     * piped output stream. <code>in&lt;0</code> implies the buffer is empty,
     * <code>in==out</code> implies the buffer is full
     */
    protected int in = -1;

    /**
     * The index of the position in the circular buffer at which the next
     * byte of data will be read by this piped input stream.
     */
    protected int out = 0;

    private XMLEvent currentEvent = null;

    /**
     * Creates a <code>PipedInputStream</code> so
     * that it is not yet PipedInputProcessor
     * connected}.
     * It must be {@linkplain java.io.PipedOutputStream#connect(
     *java.io.PipedInputStream) connected} to a
     * <code>PipedOutputStream</code> before being used.
     */
    public PipedXMLStreamReader() {
        initPipe(DEFAULT_PIPE_SIZE);
    }

    /**
     * Creates a <code>PipedInputStream</code> so that it is not yet
     * PipedInputProcessor connected and
     * uses the specified pipe size for the pipe's buffer.
     * It must be {@linkplain java.io.PipedOutputStream#connect(
     *java.io.PipedInputStream)
     * connected} to a <code>PipedOutputStream</code> before being used.
     *
     * @param pipeSize the size of the pipe's buffer.
     * @throws IllegalArgumentException if <code>pipeSize <= 0</code>.
     * @since 1.6
     */
    public PipedXMLStreamReader(int pipeSize) {
        initPipe(pipeSize);
    }

    private void initPipe(int pipeSize) {
        if (pipeSize <= 0) {
            throw new IllegalArgumentException("Pipe Size <= 0");
        }
        buffer = new XMLEvent[pipeSize];
    }

    /**
     * the writing thread must be set as early as possible
     * because the writing thread can die before it wrote
     * the first event. In this case the next() method loops
     * endless because writeSide is still null. 
     */
    public void setWriteSide(Thread writeSide) {
        this.writeSide = writeSide;
    }

    /**
     * Receives a XMLEvent.  This method will block if no input is
     * available.
     *
     * @throws java.io.IOException If the pipe is <a href=#BROKEN> <code>broken</code></a>,
     *                             PipedInputProcessor unconnected,
     *                             closed, or if an I/O error occurs.
     */
    protected synchronized void receive(XMLEvent xmlEvent) throws IOException {
        checkStateForReceive();
        //the first calling thread is the thread which must also call receivedLast()
        //this is the contract of this class!
        if (writeSide == null) {
            writeSide = Thread.currentThread();
        }
        if (in == out)
            awaitSpace();
        if (in < 0) {
            in = 0;
            out = 0;
        }
        buffer[in++] = xmlEvent;
        if (in >= buffer.length) {
            in = 0;
        }
    }

    private void checkStateForReceive() throws IOException {
        if (!connected) {
            throw new IOException("Pipe not connected");
        } else if (closedByWriter || closedByReader) {
            throw new IOException("Pipe closed");
        } else if (readSide != null && !readSide.isAlive()) {
            throw new IOException("Read end dead");
        }
    }

    private void awaitSpace() throws IOException {
        while (in == out) {
            checkStateForReceive();

            /* full: kick any waiting readers */
            notifyAll();
            try {
                wait(10);
            } catch (InterruptedException ex) {
                throw new java.io.InterruptedIOException();
            }
        }
    }

    /**
     * Notifies all waiting threads that the last byte of data has been
     * received.
     */
    synchronized void receivedLast() {
        closedByWriter = true;
        notifyAll();
    }


    public Object getProperty(String name) throws IllegalArgumentException {
        return null;
    }

    public synchronized int next() throws XMLStreamException {
        if (!connected) {
            throw new XMLStreamException("Pipe not connected");
        } else if (closedByReader) {
            throw new XMLStreamException("Pipe closed");
        } else if (writeSide != null && !writeSide.isAlive()
                && !closedByWriter && (in < 0)) {
            throw new XMLStreamException("Write end dead");
        }

        readSide = Thread.currentThread();
        int trials = 2;
        while (in < 0) {
            if (closedByWriter) {
                /* closed by writer, return EOF */
                throw new IllegalStateException("No more input available");
            }            
            else if ((writeSide != null) && (!writeSide.isAlive()) && (--trials < 0)) {
                throwSecurityException("Pipe broken");
            }
            /* might be a writer waiting */
            notifyAll();
            try {
                wait(10);
            } catch (InterruptedException ex) {
                throw new XMLStreamException(ex);
            }
        }
        currentEvent = buffer[out++];
        int ret = currentEvent.getEventType();
        if (out >= buffer.length) {
            out = 0;
        }
        if (in == out) {
            /* now empty */
            in = -1;
        }

        return ret;
    }

    private XMLEvent getCurrentEvent() {
        if (currentEvent == null) {
            throw new IllegalStateException("Illegal state");
        }
        return currentEvent;
    }

    public void require(int type, String namespaceURI, String localName) throws XMLStreamException {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != type) {
            throw new XMLStreamException("Event type mismatch");
        }

        if (localName != null) {
            if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT
                    && xmlEvent.getEventType() != ENTITY_REFERENCE) {
                throw new XMLStreamException("Expected non-null local name, but current token not a START_ELEMENT, END_ELEMENT or ENTITY_REFERENCE (was " + xmlEvent.getEventType() + ")");
            }
            String n = getLocalName();
            if (!n.equals(localName)) {
                throw new XMLStreamException("Expected local name '" + localName + "'; current local name '" + n + "'.");
            }
        }
        if (namespaceURI != null) {
            if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
                throw new XMLStreamException("Expected non-null NS URI, but current token not a START_ELEMENT or END_ELEMENT (was " + xmlEvent.getEventType() + ")");
            }
            String uri = getNamespaceURI();
            // No namespace?
            if (namespaceURI.length() == 0) {
                if (uri != null && uri.length() > 0) {
                    throw new XMLStreamException("Expected empty namespace, instead have '" + uri + "'.");
                }
            } else {
                if (!namespaceURI.equals(uri)) {
                    throw new XMLStreamException("Expected namespace '" + namespaceURI + "'; have '"
                            + uri + "'.");
                }
            }
        }
    }

    final private static int MASK_GET_ELEMENT_TEXT =
            (1 << CHARACTERS) | (1 << CDATA) | (1 << SPACE)
                    | (1 << ENTITY_REFERENCE);

    public String getElementText() throws XMLStreamException {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new XMLStreamException("Not positioned on a start element");
        }
        StringBuffer stringBuffer = new StringBuffer();

        /**
         * Need to loop to get rid of PIs, comments
         */
        while (true) {
            int type = next();
            if (type == END_ELEMENT) {
                break;
            }
            if (type == COMMENT || type == PROCESSING_INSTRUCTION) {
                continue;
            }
            if (((1 << type) & MASK_GET_ELEMENT_TEXT) == 0) {
                throw new XMLStreamException("Expected a text token, got " + xmlEvent.getEventType() + ".");
            }
            stringBuffer.append(getText());
        }
        return stringBuffer.toString();
    }

    public int nextTag() throws XMLStreamException {
        while (true) {
            int next = next();

            switch (next) {
                case SPACE:
                case COMMENT:
                case PROCESSING_INSTRUCTION:
                    continue;
                case CDATA:
                case CHARACTERS:
                    if (isWhiteSpace()) {
                        continue;
                    }
                    throw new XMLStreamException("Received non-all-whitespace CHARACTERS or CDATA event in nextTag().");
                case START_ELEMENT:
                case END_ELEMENT:
                    return next;
            }
            throw new XMLStreamException("Received event " + next
                    + ", instead of START_ELEMENT or END_ELEMENT.");
        }
    }

    public boolean hasNext() throws XMLStreamException {

        if (!connected) {
            throw new XMLStreamException("Pipe not connected");
        } else if (closedByReader) {
            throw new XMLStreamException("Pipe closed");
        } else if (writeSide != null && !writeSide.isAlive()
                && !closedByWriter && (in < 0)) {
            throw new XMLStreamException("Write end dead");
        }

        if (closedByWriter && in < 0) {
            return false;
        }
        return true;
    }

    public void close() throws XMLStreamException {
        closedByReader = true;
        synchronized (this) {
            in = -1;
        }
    }

    public String getNamespaceURI(String prefix) {
        XMLEvent xmlEvent = getCurrentEvent();

        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_ELEM);
        }

        if (xmlEvent.isStartElement()) {
            return xmlEvent.asStartElement().getNamespaceURI(prefix);
        } else {
            //todo somehow...
            return null;
        }
    }

    public boolean isStartElement() {
        XMLEvent xmlEvent = getCurrentEvent();
        return xmlEvent.isStartElement();
    }

    public boolean isEndElement() {
        XMLEvent xmlEvent = getCurrentEvent();
        return xmlEvent.isEndElement();
    }

    public boolean isCharacters() {
        XMLEvent xmlEvent = getCurrentEvent();
        return xmlEvent.isCharacters();
    }

    public boolean isWhiteSpace() {
        XMLEvent xmlEvent = getCurrentEvent();
        return xmlEvent.isCharacters() && xmlEvent.asCharacters().isWhiteSpace();
    }

    public String getAttributeValue(String namespaceURI, String localName) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        Attribute attribute = xmlEvent.asStartElement().getAttributeByName(new QName(namespaceURI, localName));
        if (attribute != null) {
            return attribute.getValue();
        }
        return null;
    }

    public int getAttributeCount() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            attributeIterator.next();
            count++;
        }
        return count;
    }

    public QName getAttributeName(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getName();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getAttributeNamespace(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getName().getNamespaceURI();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getAttributeLocalName(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getName().getLocalPart();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getAttributePrefix(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getName().getPrefix();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getAttributeType(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getDTDType();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getAttributeValue(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.getValue();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public boolean isAttributeSpecified(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Attribute> attributeIterator = xmlEvent.asStartElement().getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (count == index) {
                return attribute.isSpecified();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public int getNamespaceCount() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            namespaceIterator.next();
            count++;
        }
        return count;
    }

    public String getNamespacePrefix(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            if (count == index) {
                return namespace.getPrefix();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public String getNamespaceURI(int index) {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        int count = 0;
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            if (count == index) {
                return namespace.getNamespaceURI();
            }
            count++;
        }
        throw new ArrayIndexOutOfBoundsException(index);
    }

    public NamespaceContext getNamespaceContext() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_STELEM);
        }
        return xmlEvent.asStartElement().getNamespaceContext();
    }

    public int getEventType() {
        XMLEvent xmlEvent = getCurrentEvent();
        return xmlEvent.getEventType();
    }

    final private static int MASK_GET_TEXT =
            (1 << CHARACTERS) | (1 << CDATA) | (1 << SPACE)
                    | (1 << COMMENT) | (1 << DTD) | (1 << ENTITY_REFERENCE);

    public String getText() {
        XMLEvent xmlEvent = getCurrentEvent();

        if (((1 << xmlEvent.getEventType()) & MASK_GET_TEXT) == 0) {
            throw new IllegalStateException("Current state not TEXT");
        }
        if (xmlEvent.getEventType() == ENTITY_REFERENCE) {
            return ((EntityReference) xmlEvent).getDeclaration().getReplacementText();
        }
        if (xmlEvent.getEventType() == DTD) {
            return ((javax.xml.stream.events.DTD) xmlEvent).getDocumentTypeDeclaration();
        }
        if (xmlEvent.getEventType() == COMMENT) {
            return ((Comment) xmlEvent).getText();
        }
        return xmlEvent.asCharacters().getData();
    }

    final private static int MASK_GET_TEXT_XXX =
            (1 << CHARACTERS) | (1 << CDATA) | (1 << SPACE) | (1 << COMMENT);

    public char[] getTextCharacters() {
        XMLEvent xmlEvent = getCurrentEvent();

        if (((1 << xmlEvent.getEventType()) & MASK_GET_TEXT_XXX) == 0) {
            throw new IllegalStateException("Current state not TEXT");
        }
        if (xmlEvent.getEventType() == ENTITY_REFERENCE) {
            return ((EntityReference) xmlEvent).getDeclaration().getReplacementText().toCharArray();
        }
        if (xmlEvent.getEventType() == DTD) {
            return ((javax.xml.stream.events.DTD) xmlEvent).getDocumentTypeDeclaration().toCharArray();
        }
        if (xmlEvent.getEventType() == COMMENT) {
            return ((Comment) xmlEvent).getText().toCharArray();
        }
        return xmlEvent.asCharacters().getData().toCharArray();
    }

    public int getTextCharacters(int sourceStart, char[] target, int targetStart, int length) throws XMLStreamException {
        XMLEvent xmlEvent = getCurrentEvent();

        if (((1 << xmlEvent.getEventType()) & MASK_GET_TEXT_XXX) == 0) {
            throw new IllegalStateException("Current state not TEXT");
        }
        if (xmlEvent.getEventType() == ENTITY_REFERENCE) {
            ((EntityReference) xmlEvent).getDeclaration().getReplacementText().getChars(sourceStart, sourceStart + length, target, targetStart);
            return sourceStart + length;
        }
        if (xmlEvent.getEventType() == DTD) {
            ((javax.xml.stream.events.DTD) xmlEvent).getDocumentTypeDeclaration().getChars(sourceStart, sourceStart + length, target, targetStart);
            return sourceStart + length;
        }
        if (xmlEvent.getEventType() == COMMENT) {
            ((Comment) xmlEvent).getText().getChars(sourceStart, sourceStart + length, target, targetStart);
            return sourceStart + length;
        }
        xmlEvent.asCharacters().getData().getChars(sourceStart, sourceStart + length, target, targetStart);
        return sourceStart + length;
    }

    public int getTextStart() {
        return 0;
    }

    public int getTextLength() {
        XMLEvent xmlEvent = getCurrentEvent();

        if (((1 << xmlEvent.getEventType()) & MASK_GET_TEXT_XXX) == 0) {
            throw new IllegalStateException("Current state not TEXT");
        }
        if (xmlEvent.getEventType() == ENTITY_REFERENCE) {
            return ((EntityReference) xmlEvent).getDeclaration().getReplacementText().length();
        }
        if (xmlEvent.getEventType() == DTD) {
            return ((javax.xml.stream.events.DTD) xmlEvent).getDocumentTypeDeclaration().length();
        }
        if (xmlEvent.getEventType() == COMMENT) {
            return ((Comment) xmlEvent).getText().length();
        }
        return xmlEvent.asCharacters().getData().length();
    }

    public String getEncoding() {
        return null;
    }

    public boolean hasText() {
        XMLEvent xmlEvent = getCurrentEvent();
        return (((1 << xmlEvent.getEventType()) & MASK_GET_TEXT) != 0);
    }

    public Location getLocation() {
        return new Location() {
            public int getLineNumber() {
                return -1;
            }

            public int getColumnNumber() {
                return -1;
            }

            public int getCharacterOffset() {
                return -1;
            }

            public String getPublicId() {
                return null;
            }

            public String getSystemId() {
                return null;
            }
        };
    }

    public QName getName() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_ELEM);
        }
        if (xmlEvent.isStartElement()) {
            return xmlEvent.asStartElement().getName();
        } else {
            return xmlEvent.asEndElement().getName();
        }
    }

    public String getLocalName() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_ELEM);
        }
        if (xmlEvent.isStartElement()) {
            return xmlEvent.asStartElement().getName().getLocalPart();
        } else {
            return xmlEvent.asEndElement().getName().getLocalPart();
        }
    }

    public boolean hasName() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            return false;
        }
        return true;
    }

    public String getNamespaceURI() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_ELEM);
        }
        if (xmlEvent.isStartElement()) {
            return xmlEvent.asStartElement().getName().getNamespaceURI();
        } else {
            return xmlEvent.asEndElement().getName().getNamespaceURI();
        }
    }

    public String getPrefix() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != START_ELEMENT && xmlEvent.getEventType() != END_ELEMENT) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_ELEM);
        }
        if (xmlEvent.isStartElement()) {
            return xmlEvent.asStartElement().getName().getPrefix();
        } else {
            return xmlEvent.asEndElement().getName().getPrefix();
        }
    }

    public String getVersion() {
        return null;
    }

    public boolean isStandalone() {
        return false;
    }

    public boolean standaloneSet() {
        return false;
    }

    public String getCharacterEncodingScheme() {
        return null;
    }

    public String getPITarget() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != PROCESSING_INSTRUCTION) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_PI);
        }
        return ((ProcessingInstruction) xmlEvent).getTarget();
    }

    public String getPIData() {
        XMLEvent xmlEvent = getCurrentEvent();
        if (xmlEvent.getEventType() != PROCESSING_INSTRUCTION) {
            throw new IllegalStateException(ErrorConsts.ERR_STATE_NOT_PI);
        }
        return ((ProcessingInstruction) xmlEvent).getData();
    }

    private void throwSecurityException(String message) throws XMLStreamException {
        if (this.thrownExceptionByWriter != null) {
            if (this.thrownExceptionByWriter instanceof UncheckedXMLSecurityException) {
                UncheckedXMLSecurityException uxse = (UncheckedXMLSecurityException)this.thrownExceptionByWriter;
                if (uxse.getCause() instanceof XMLStreamException) {
                    throw (XMLStreamException)uxse.getCause();
                } else {
                    throw new XMLStreamException(uxse.getCause());
                }
            }
            else {
                throw new XMLStreamException(this.thrownExceptionByWriter);
            }
        } else {
            throw new XMLStreamException(message);
        }
    }

    public void uncaughtException(Thread t, Throwable e) {
        thrownExceptionByWriter = e;
    }
}
