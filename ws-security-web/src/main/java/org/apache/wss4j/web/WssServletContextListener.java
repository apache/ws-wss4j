package org.apache.wss4j.web;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.wss4j.dom.engine.WSSConfig;

/**
 * ServletContextListener that cleans up WSS4J security providers at context
 * destruction.
 */
@WebListener
public class WssServletContextListener implements ServletContextListener {

  @Override
  public void contextDestroyed(ServletContextEvent servletContextEvent) {
    WSSConfig.cleanUp();
  }

  @Override
  public void contextInitialized(ServletContextEvent servletContextEvent) {
  }

}
