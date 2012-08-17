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
package org.apache.ws.security.stax.wss.test;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WsuIdAllocator;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.util.UUIDGenerator;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.ws.security.stax.wss.WSSec;
import org.apache.ws.security.stax.wss.ext.*;
import org.apache.ws.security.stax.wss.test.utils.SOAPUtil;
import org.apache.ws.security.stax.wss.test.utils.StAX2DOM;
import org.apache.ws.security.stax.wss.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractTestBase {

    //javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
    //transformer.transform(new StreamSource(new ByteArrayInputStream(baos.toByteArray())), new StreamResult(System.out));

    protected static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    protected static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
    protected DocumentBuilderFactory documentBuilderFactory;

    protected static final String SECURED_DOCUMENT = "securedDocument";

    static {
        LogManager.getLogManager().addLogger(Logger.getLogger("org.jcp.xml.dsig.internal.dom"));
        LogManager.getLogManager().getLogger("org.jcp.xml.dsig.internal.dom").setLevel(Level.FINE);

        Security.addProvider(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    //we have to set a custom baseUUID until WSS4J-DOM is fixed. WSS4J generates invalid id's. (wsu:id's must start with a letter)
    static {
        try {
            Field field = UUIDGenerator.class.getDeclaredField("baseUUID");
            field.setAccessible(true);
            field.set(null, "G" + UUID.randomUUID().toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeClass
    public void insertBC() {
        //we need an JCE provider which understands elliptic curve cryptography.
        //the sun default provider also supports ec but returns a sun.security.x509.X509Key
        //instead of the java.security.interfaces.ECPublicKey. Bug?
        // Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 2);
        try {
            Class<?> c = 
                XMLSec.class.getClassLoader().loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            if (null == Security.getProvider("BC")) {
                Security.addProvider((Provider) c.newInstance());
            }
        } catch (Throwable e) {
            // throw new RuntimeException("Adding BouncyCastle provider failed", e);
        }

    }

    @AfterClass
    public void removeBC() {
        Security.removeProvider("BC");
    }

    public AbstractTestBase() {
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringComments(false);
        documentBuilderFactory.setCoalescing(false);
        documentBuilderFactory.setIgnoringElementContentWhitespace(false);
        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        //xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(5 * 8192));
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream,
                                      SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream,
                                      List<SecurityEvent> securityEventList, SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventList, securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader) throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlStreamReader, null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader, SecurityEventListener securityEventListener) throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlStreamReader, new ArrayList<SecurityEvent>(), securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader, List<SecurityEvent> securityEventList, SecurityEventListener securityEventListener) throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, securityEventList, securityEventListener);
        return StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), outXmlStreamReader);
    }

    protected ByteArrayOutputStream doOutboundSecurity(WSSSecurityProperties securityProperties, InputStream sourceDocument) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return baos;
    }

    protected Document doOutboundSecurityWithWSS4J(InputStream sourceDocument, String action, Properties properties) throws WSSecurityException {
        Map<String, Object> context = doOutboundSecurityWithWSS4J_1(sourceDocument, action, properties);
        return (Document) context.get(SECURED_DOCUMENT);
    }

    protected Map<String, Object> doOutboundSecurityWithWSS4J_1(
            InputStream sourceDocument, String action, final Properties properties
    ) throws WSSecurityException {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        final Map<String, Object> messageContext = getMessageContext(sourceDocument);
        messageContext.put(WSHandlerConstants.ACTION, action);
        messageContext.put(WSHandlerConstants.USER, "transmitter");

        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.put("" + sigProperties.hashCode(), sigProperties);

        Properties encProperties = new Properties();
        encProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        encProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        encProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.put(WSHandlerConstants.ENCRYPTION_USER, "receiver");
        messageContext.put(WSHandlerConstants.ENC_PROP_REF_ID, "" + encProperties.hashCode());
        messageContext.put("" + encProperties.hashCode(), encProperties);

        Enumeration<?> enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.put(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        requestData.setNoSerialization(true);
        requestData.setCallbackHandler(new WSS4JCallbackHandlerImpl());
        //we have to set a custom IDAllocator until WSS4J-DOM is fixed. WSS4J generates invalid id's. (wsu:id's must start with a letter)
        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.getWssConfig().setIdAllocator(new WsuIdAllocator() {
            @Override
            public String createId(String prefix, Object o) {
                return createSecureId(prefix, o);
            }

            @Override
            public String createSecureId(String prefix, Object o) {
                String id = UUID.randomUUID().toString();
                if (prefix != null) {
                    return prefix + id;
                } else {
                    return "G" + id;
                }
            }
        });

        wss4JHandler.doSender(messageContext, requestData, true);

        return messageContext;
    }

    protected Document doInboundSecurityWithWSS4J(Document document, String action) throws Exception {
        Map<String, Object> messageContext = doInboundSecurityWithWSS4J_1(document, action);
        return ((Document) messageContext.get(SECURED_DOCUMENT));
    }

    protected Map<String, Object> doInboundSecurityWithWSS4J_1(Document document, String action) throws Exception {
        return doInboundSecurityWithWSS4J_1(document, action, new Properties(), false);
    }

    protected Map<String, Object> doInboundSecurityWithWSS4J_1(
            Document document, String action, Properties properties, boolean client
    ) throws Exception {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        Map<String, Object> messageContext = getMessageContext(document);
        messageContext.put(WSHandlerConstants.ACTION, action);
        if (client) {
            messageContext.put(WSHandlerConstants.USER, "transmitter");
        } else {
            messageContext.put(WSHandlerConstants.USER, "receiver");
        }

        //handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTOR, "receiver");
        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        if (client) {
            sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        } else {
            sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        }
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");

        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.put("" + sigProperties.hashCode(), sigProperties);
        if (properties.get(WSHandlerConstants.PW_CALLBACK_REF) != null) {
            messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, properties.get(WSHandlerConstants.PW_CALLBACK_REF));
        } else {
            messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, new WSS4JCallbackHandlerImpl());
        }

        Properties decProperties = new Properties();
        decProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        if (client) {
            decProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        } else {
            decProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        }
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        decProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.put(WSHandlerConstants.DEC_PROP_REF_ID, "" + decProperties.hashCode());
        messageContext.put("" + decProperties.hashCode(), decProperties);

        Enumeration<?> enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.put(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        wss4JHandler.doReceiver(messageContext, requestData, false);

        return messageContext;
    }

    private Map<String, Object> getMessageContext(InputStream inputStream) {
        Map<String, Object> context = new HashMap<String, Object>();
        try {
            context.put(SECURED_DOCUMENT, SOAPUtil.toSOAPPart(inputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return context;
    }

    private Map<String, Object> getMessageContext(Document document) {
        Map<String, Object> context = new HashMap<String, Object>();
        context.put(SECURED_DOCUMENT, document);
        return context;
    }

    protected XPathExpression getXPath(String expression) throws XPathExpressionException {
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xPath = xPathFactory.newXPath();
        xPath.setNamespaceContext(
                new NamespaceContext() {
                    public String getNamespaceURI(String prefix) {
                        if (WSSConstants.PREFIX_DSIG.equals(prefix)) {
                            return WSSConstants.NS_DSIG;
                        } else if (WSSConstants.PREFIX_SOAPENV.equals(prefix)) {
                            return WSSConstants.NS_SOAP11;
                        } else if (WSSConstants.PREFIX_WSSE.equals(prefix)) {
                            return WSSConstants.NS_WSSE10;
                        } else if (WSSConstants.PREFIX_WSU.equals(prefix)) {
                            return WSSConstants.NS_WSU10;
                        } else if (WSSConstants.PREFIX_XENC.equals(prefix)) {
                            return WSSConstants.NS_XMLENC;
                        } else {
                            return null;
                        }
                    }

                    public String getPrefix(String namespaceURI) {
                        if (WSSConstants.NS_DSIG.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_DSIG;
                        } else if (WSSConstants.NS_SOAP11.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_SOAPENV;
                        } else if (WSSConstants.NS_WSSE10.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_WSSE;
                        } else if (WSSConstants.NS_WSU10.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_WSU;
                        } else if (WSSConstants.NS_XMLENC.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_XENC;
                        } else {
                            return null;
                        }
                    }

                    public Iterator<String> getPrefixes(String namespaceURI) {
                        return null;
                    }
                }
        );
        return xPath.compile(expression);
    }

    class CustomWSS4JHandler extends WSHandler {

        private final Log log = LogFactory.getLog(CustomWSS4JHandler.class.getName());
        private final boolean doDebug = log.isDebugEnabled();

        /**
         * Handles incoming web service requests and outgoing responses
         */
        public boolean doSender(Map<String, Object> mc, RequestData reqData, boolean isRequest)
                throws WSSecurityException {

            reqData.getSignatureParts().clear();
            reqData.getEncryptParts().clear();
            /*
             * Get the action first.
             */
            String action = (String) mc.get(WSHandlerConstants.ACTION);
            if (action == null) {
                throw new WSSecurityException("WSS4JHandler: No action defined");
            }
            List<Integer> actions = new ArrayList<Integer>();
            int doAction = WSSecurityUtil.decodeAction(action, actions);
            if (doAction == WSConstants.NO_SECURITY) {
                return true;
            }

            /*
            * For every action we need a username, so get this now. The username
            * defined in the deployment descriptor takes precedence.
            */
            reqData.setUsername((String) getOption(WSHandlerConstants.USER));
            if (reqData.getUsername() == null || reqData.getUsername().equals("")) {
                reqData.setUsername((String) mc.get(WSHandlerConstants.USER));
            }

            /*
            * Now we perform some set-up for UsernameToken and Signature
            * functions. No need to do it for encryption only. Check if username
            * is available and then get a password.
            */
            if (((doAction & (WSConstants.SIGN | WSConstants.UT | WSConstants.UT_SIGN)) != 0)
                    && (reqData.getUsername() == null || reqData.getUsername().equals(""))) {
                /*
                 * We need a username - if none throw a WSSecurityException. For encryption
                 * there is a specific parameter to get a username.
                 */
                throw new WSSecurityException(
                        "WSS4JHandler: Empty username for specified action"
                );
            }
            if (doDebug) {
                log.debug("Action: " + doAction);
                log.debug("Actor: " + reqData.getActor());
            }
            /*
            * Now get the SOAP part from the request message and convert it into a
            * Document.
            *
            * Now we can perform our security operations on this request.
            */
            Document doc = (Document) mc.get(SECURED_DOCUMENT);
            if (doc == null) {
                throw new WSSecurityException(
                        "WSS4JHandler: cannot get SOAP envlope from message"
                );
            }
            if (doDebug) {
                log.debug("WSS4JHandler: orginal SOAP request: ");
                log.debug(org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc));
            }
            doSenderAction(doAction, doc, reqData, actions, isRequest);

            mc.put(SECURED_DOCUMENT, doc);

            return true;
        }

        @SuppressWarnings("unchecked")
        public boolean doReceiver(Map<String, Object> mc, RequestData reqData, boolean isRequest)
                throws WSSecurityException {
            String action = (String) mc.get(WSHandlerConstants.ACTION);
            if (action == null) {
                throw new WSSecurityException("WSS4JHandler: No action defined");
            }
            List<Integer> actions = new ArrayList<Integer>();
            int doAction = WSSecurityUtil.decodeAction(action, actions);

            String actor = (String) mc.get(WSHandlerConstants.ACTOR);

            Document doc = (Document) mc.get(SECURED_DOCUMENT);

            /*
             * Check if it's a fault. Don't process faults.
             */
            org.apache.ws.security.SOAPConstants soapConstants =
                    WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
            if (WSSecurityUtil.findElement(
                    doc.getDocumentElement(), "Fault", soapConstants.getEnvelopeURI()) != null
                    ) {
                return false;
            }

            /*
             * To check a UsernameToken or to decrypt an encrypted message we need
             * a password.
             */
            CallbackHandler cbHandler = getPasswordCallbackHandler(reqData);
            reqData.setCallbackHandler(cbHandler);

            /*
             * Get and check the Signature specific parameters first because they
             * may be used for encryption too.
             */
            doReceiverAction(doAction, reqData);

            Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);

            List<WSSecurityEngineResult> wsResult = null;
            try {
                wsResult = secEngine.processSecurityHeader(elem, reqData);
            } catch (WSSecurityException ex) {
                if (doDebug) {
                    log.debug(ex.getMessage(), ex);
                }
                throw new WSSecurityException(
                        "WSS4JHandler: security processing failed", ex
                );
            }
            if (wsResult == null || wsResult.size() == 0) {
                // no security header found
                if (doAction == WSConstants.NO_SECURITY) {
                    return true;
                } else {
                    throw new WSSecurityException(
                            "WSS4JHandler: Request does not contain required Security header"
                    );
                }
            }
            if (reqData.getWssConfig().isEnableSignatureConfirmation() && !isRequest) {
                checkSignatureConfirmation(reqData, wsResult);
            }

            if (doDebug) {
                log.debug("Processed received SOAP request");
            }

            /*
             * now check the security actions: do they match, in right order?
             */
            if (!checkReceiverResults(wsResult, actions)) {
                throw new WSSecurityException(
                        "WSS4JHandler: security processing failed (actions mismatch)"
                );
            }

            /*
             * All ok up to this point. Now construct and setup the
             * security result structure. The service may fetch this
             * and check it.
             */
            List<WSHandlerResult> results = null;
            if ((results = (List<WSHandlerResult>) mc.get(WSHandlerConstants.RECV_RESULTS)) == null) {
                results = new ArrayList<WSHandlerResult>();
                mc.put(WSHandlerConstants.RECV_RESULTS, results);
            }
            WSHandlerResult rResult = new WSHandlerResult(actor, wsResult);
            results.add(0, rResult);
            if (doDebug) {
                log.debug("WSS4JHandler: exit invoke()");
            }

            return true;
        }

        protected boolean checkReceiverResults(
                List<WSSecurityEngineResult> wsResult, List<Integer> actions
        ) {
            List<WSSecurityEngineResult> wsSecurityEngineResults = new ArrayList<WSSecurityEngineResult>();
            for (WSSecurityEngineResult result : wsResult) {
                boolean found = false;
                for (WSSecurityEngineResult res : wsSecurityEngineResults) {
                    if (((Integer) result.get(WSSecurityEngineResult.TAG_ACTION)).equals((Integer) res.get(WSSecurityEngineResult.TAG_ACTION))) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    wsSecurityEngineResults.add(result);
                }
            }
            int size = actions.size();
            int ai = 0;
            for (WSSecurityEngineResult result : wsSecurityEngineResults) {
                final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
                int act = actInt.intValue();
                if (act == WSConstants.SC || act == WSConstants.BST || act == WSConstants.DKT || act == WSConstants.SCT || act == WSConstants.UT_NOPASSWORD) {
                    continue;
                }

                if (ai >= size || actions.get(ai++).intValue() != act) {
                    return false;
                }
            }
            /*
        if (ai != size) {
            return false;
        }
             */
            return true;
        }

        public Object getOption(String key) {
            return null;
        }

        @SuppressWarnings("unchecked")
        public Object getProperty(Object msgContext, String key) {
            return ((Map<String, Object>) msgContext).get(key);
        }

        @SuppressWarnings("unchecked")
        public void setProperty(Object msgContext, String key, Object value) {
            ((Map<String, Object>) msgContext).put(key, value);
        }

        @SuppressWarnings("unchecked")
        public String getPassword(Object msgContext) {
            return (String) ((Map<String, Object>) msgContext).get("password");
        }

        @SuppressWarnings("unchecked")
        public void setPassword(Object msgContext, String password) {
            ((Map<String, Object>) msgContext).put("password", password);
        }
    }

    protected class TestSecurityEventListener implements SecurityEventListener {
        private SecurityEventConstants.Event[] expectedEvents;
        private List<SecurityEvent> receivedSecurityEvents = new ArrayList<SecurityEvent>();

        public TestSecurityEventListener(SecurityEventConstants.Event[] expectedEvents) {
            this.expectedEvents = expectedEvents;
        }

        public List<SecurityEvent> getReceivedSecurityEvents() {
            return receivedSecurityEvents;
        }

        @Override
        public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
            receivedSecurityEvents.add(securityEvent);
        }

        public void compare() {
            if (expectedEvents.length != receivedSecurityEvents.size()) {
                printEvents();
                Assert.fail("event count mismatch");
            }
            boolean asserted = true;
            for (int i = 0; i < expectedEvents.length; i++) {
                if (!expectedEvents[i].equals(receivedSecurityEvents.get(i).getSecurityEventType())) {
                    asserted = false;
                    break;
                }
            }
            if (!asserted) {
                printEvents();
                Assert.fail("event mismatch");
            }
        }

        private void printEvents() {
            System.out.println("expected events:");
            for (int i = 0; i < expectedEvents.length; i++) {
                SecurityEventConstants.Event expectedEvent = expectedEvents[i];
                System.out.println("SecurityEvent.Event." + expectedEvent + ",");
            }
            System.out.println("received events:");
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                System.out.println("SecurityEvent.Event." + securityEvent.getSecurityEventType() + ",");
            }
        }
    }
}
