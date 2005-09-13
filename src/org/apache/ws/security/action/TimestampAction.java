package org.apache.ws.security.action;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.message.WSAddTimestamp;
import org.w3c.dom.Document;

public class TimestampAction implements Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        WSAddTimestamp timeStampBuilder =
                new WSAddTimestamp(reqData.getActor(), mu);
        timeStampBuilder.setWsConfig(reqData.getWssConfig());


        timeStampBuilder.setId("Timestamp-" + System.currentTimeMillis());

        // add the Timestamp to the SOAP Enevelope
        timeStampBuilder.build(doc, handler.decodeTimeToLive(reqData));
    }
}
