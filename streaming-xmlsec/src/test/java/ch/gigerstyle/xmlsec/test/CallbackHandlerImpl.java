package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.ext.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class CallbackHandlerImpl implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];

        if (pc.getUsage() == WSPasswordCallback.DECRYPT || pc.getUsage() == WSPasswordCallback.SIGNATURE) {
            pc.setPassword("refApp9876");
        } else {
            throw new UnsupportedCallbackException(pc, "Unrecognized CallbackHandlerImpl");
        }
    }
}
