package wssec;

import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.dom.DOMSource;
import java.io.ByteArrayInputStream;

public class SOAPUtil {

    /**
     * Convert a DOM Document into a soap message.
     * <p/>
     *
     * @param doc
     * @return
     * @throws Exception
     */
    public static SOAPMessage toSOAPMessage(Document doc) throws Exception {
        Canonicalizer c14n =
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        byte[] canonicalMessage = c14n.canonicalizeSubtree(doc);
        ByteArrayInputStream in = new ByteArrayInputStream(canonicalMessage);
        MessageFactory factory = MessageFactory.newInstance();
        return factory.createMessage(null, in);
    }

    /**
     * Update soap message.
     * <p/>
     *
     * @param doc
     * @param message
     * @return
     * @throws Exception
     */
    public static SOAPMessage updateSOAPMessage(Document doc,
                                                SOAPMessage message)
            throws Exception {
        DOMSource domSource = new DOMSource(doc);
        message.getSOAPPart().setContent(domSource);
        return message;
    }
}
