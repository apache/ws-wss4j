package org.apache.ws.security.processor;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSDocInfo;
import org.w3c.dom.Element;

import java.util.Vector;

public interface Processor {
    public void handleToken(Element elem, WSDocInfo wsDocInfo, Vector returnResults) throws WSSecurityException;
}
