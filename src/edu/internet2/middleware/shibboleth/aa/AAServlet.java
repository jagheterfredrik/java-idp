/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.opensaml.QName;
import org.opensaml.SAMLException;
import org.opensaml.SAMLIdentifier;

import edu.internet2.middleware.eduPerson.Init;
import edu.internet2.middleware.shibboleth.aa.arp.AAPrincipal;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.hs.HandleException;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryFactory;

/**
 *  Attribute Authority & Release Policy
 *  Handles Initialization and incoming requests to AA
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

public class AAServlet extends HttpServlet {

    protected AAResponder responder;
    protected HandleRepository handleRepository;
    protected Properties configuration;
    private static Logger log = Logger.getLogger(AAServlet.class.getName());    
    
	public void init() throws ServletException {
		super.init();

		MDC.put("serviceId", "[AA Core]");
		log.info("Initializing Attribute Authority.");

		try {

			configuration = loadConfiguration();

			ArpEngine arpEngine = new ArpEngine(configuration);
			
			handleRepository = HandleRepositoryFactory.getInstance(configuration);

			log.info(
				"Using JNDI context ("
					+ configuration.getProperty("java.naming.factory.initial")
					+ ") for attribute retrieval.");

			DirContext ctx = new InitialDirContext(configuration);
			Init.init();
			responder =
				new AAResponder(
					arpEngine,
					ctx,
					configuration.getProperty(
						"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName"));

			log.info("Attribute Authority initialization complete.");

		} catch (NamingException ne) {
			log.fatal(
				"The AA could not be initialized due to a problem with the JNDI context configuration: "
					+ ne);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (ArpException ae) {
			log.fatal(
				"The AA could not be initialized due to a problem with the ARP Engine configuration: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (AAException ae) {
			log.fatal("The AA could not be initialized: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (HandleRepositoryException he) {
			log.fatal(
				"The AA could not be initialized due to a problem with the Handle Repository configuration: "
					+ he);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		}
	}
	protected Properties loadConfiguration() throws AAException {

		//Set defaults
		Properties defaultProps = new Properties();
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path",
			getServletContext().getRealPath("/WEB-INF/conf/arps/"));
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName",
			"shib2.internet2.edu");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.ldapUserDnPhrase", "uid=");
		defaultProps.setProperty(
			"java.naming.factory.initial",
			"edu.internet2.middleware.shibboleth.aaLocal.EchoCtxFactory");

		//Load from file
		Properties properties = new Properties(defaultProps);
		String propertiesFileLocation = getInitParameter("OriginPropertiesFile");
		if (propertiesFileLocation == null) {
			propertiesFileLocation = "/WEB-INF/conf/origin.properties";
		}
		try {
			log.debug("Loading Configuration from (" + propertiesFileLocation + ").");
			properties.load(getServletContext().getResourceAsStream(propertiesFileLocation));
		} catch (IOException e) {
			log.error("Could not load AA servlet configuration: " + e);
			throw new AAException("Could not load AA servlet configuration.");
		}

		if (log.isDebugEnabled()) {
			ByteArrayOutputStream debugStream = new ByteArrayOutputStream();
			PrintStream debugPrinter = new PrintStream(debugStream);
			properties.list(debugPrinter);
			log.debug(
				"Runtime configuration parameters: "
					+ System.getProperty("line.separator")
					+ debugStream.toString());
		}

		return properties;
	}

	public void doPost(HttpServletRequest req, HttpServletResponse resp)
		throws ServletException, IOException {

		log.debug("Recieved a request.");
		MDC.put("serviceId", new SAMLIdentifier().toString());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		List attrs = null;
		SAMLException ourSE = null;
		AASaml saml = null;
		Principal principal = null;

		try {
			saml =
				new AASaml(
					configuration.getProperty(
						"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName"));
			saml.receive(req);

			URL resource = null;
			try {
				resource = new URL(saml.getResource());
			} catch (MalformedURLException mue) {
				log.error(
					"Request contained an improperly formatted resource identifier.  Attempting to "
						+ "handle request without one.");
			}

			String shar = saml.getShar();
			log.info("AA: shar:" + shar);
			String handle = saml.getHandle();
			log.info("AA: handle:" + handle);
			if (handle.equalsIgnoreCase("foo")) {
				// for testing only
				new AAPrincipal("dummy");
			} else {
				principal = handleRepository.getPrincipal(handle);
				if (principal == null) {
					throw new HandleException("Received a request for an invalid/unknown handle.");
				}
			}

			attrs =
				Arrays.asList(
					responder.getReleaseAttributes(
						principal,
						configuration.getProperty(
							"edu.internet2.middleware.shibboleth.aa.AAServlet.ldapUserDnPhrase"),
						shar,
						resource));
			log.info("Got " + attrs.size() + " attributes for " + principal.getName());
			saml.respond(resp, attrs, null);
			log.info("Successfully responded about " + principal.getName());

		} catch (org.opensaml.SAMLException se) {
			log.error("AA failed for " + principal.getName() + " because of: " + se);
			try {
				saml.fail(resp, se);
			} catch (Exception ee) {
				throw new ServletException(
					"AA failed to even make a SAML Failure message because "
						+ ee
						+ "  Origianl problem: "
						+ se);
			}
		} catch (HandleException he) {
			log.error("AA failed for " + principal.getName() + " because of: " + he);
			try {
				QName[] codes = new QName[2];
				codes[0] = SAMLException.REQUESTER;
				codes[1] =
					new QName(
						edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,
						"InvalidHandle");
				saml.fail(
					resp,
					new SAMLException(Arrays.asList(codes), "AA got a HandleException: " + he));
			} catch (Exception ee) {
				throw new ServletException(
					"AA failed to even make a SAML Failure message because "
						+ ee
						+ "  Original problem: "
						+ he);
			}
		} catch (Exception e) {
			e.printStackTrace();
			log.error(
				"Attribute Authority Error for principal ("
					+ principal.getName()
					+ ") : "
					+ e.getClass().getName()
					+ " : "
					+ e.getMessage());
			try {
				saml.fail(
					resp,
					new SAMLException(
						SAMLException.RESPONDER,
						"Attribute Authority Error: " + e.getMessage()));
			} catch (Exception ee) {
				throw new ServletException(
					"AA failed to even make a SAML Failure message because "
						+ ee
						+ "  Original problem: "
						+ e);
			}

		}
	}


}
