package org.apache.ws.security.action;

import org.w3c.dom.Document;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.WSSecurityException;

/**
 * Interface for all actions
 */
public interface Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData) throws WSSecurityException;
}
