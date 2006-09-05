/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectStatement;
import org.opensaml.artifact.Artifact;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;
import edu.internet2.middleware.shibboleth.idp.RequestHandlingException;

/**
 * <code>ProtocolHandler</code> implementation that responds to SSO flows as specified in "Shibboleth Architecture:
 * Protocols and Profiles".
 * 
 * @author Walter Hoehn
 */
public class ShibbolethV1SSOHandler extends SSOHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(ShibbolethV1SSOHandler.class.getName());

	/**
	 * Required DOM-based constructor.
	 */
	public ShibbolethV1SSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void processRequest(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support)
			throws RequestHandlingException, ServletException {

		try {

			// Set attributes that are needed by the jsp
			request.setAttribute("shire", request.getParameter("shire"));
			request.setAttribute("target", request.getParameter("target"));

			// Ensure that we have the required data from the servlet container
			validateEngineData(request);
			validateShibSpecificData(request);

			// Get the authN info
			String username = support.getIdPConfig().getAuthHeaderName().equalsIgnoreCase("REMOTE_USER") ? request
					.getRemoteUser() : request.getHeader(support.getIdPConfig().getAuthHeaderName());
			if ((username == null) || (username.equals(""))) { throw new InvalidClientDataException(
					"Unauthenticated principal. This protocol handler requires that authentication information be "
							+ "provided from the servlet container."); }
			LocalPrincipal principal = new LocalPrincipal(username);

			// Select the appropriate Relying Party configuration for the request
			RelyingParty relyingParty = null;
			String remoteProviderId = request.getParameter("providerId");
			// If the SP did not send a Provider Id, then assume it is a Shib
			// 1.1 or older SP
			if (remoteProviderId == null || remoteProviderId.equals("")) {
				throw new InvalidClientDataException("Invalid or missing service provider id.");
			} else {
				log.debug("Remote provider has identified itself as: (" + remoteProviderId + ").");
				relyingParty = support.getServiceProviderMapper().getRelyingParty(remoteProviderId);
			}

			// Grab the metadata for the provider
			EntityDescriptor descriptor = null;
			try {
				descriptor = support.getEntityDescriptor(relyingParty.getProviderId());
			} catch (MetadataProviderException e1) {
				log.error("Metadata lookup for provider (" + relyingParty.getProviderId() + ") encountered an error: "
						+ e1);
			}

			// Make sure that the selected relying party configuration is appropriate for this
			// acceptance URL
			String acceptanceURL = request.getParameter("shire");

			if (descriptor == null) {
				log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
				relyingParty = support.getServiceProviderMapper().getRelyingParty(null);

			} else {
				if (isValidAssertionConsumerURL(descriptor, acceptanceURL)) {
					log.info("Supplied consumer URL validated for this provider.");
				} else {
					log.error("Assertion consumer service URL (" + acceptanceURL + ") is NOT valid for provider ("
							+ relyingParty.getProviderId() + ").");
					throw new InvalidClientDataException("Invalid assertion consumer service URL.");
				}
			}

			// Create SAML Name Identifier & Subject
			SAMLNameIdentifier nameId;

			nameId = getNameIdentifier(support.getNameMapper(), principal, relyingParty, descriptor);

			String authenticationMethod = request.getHeader("SAMLAuthenticationMethod");
			if (authenticationMethod == null || authenticationMethod.equals("")) {
				authenticationMethod = relyingParty.getDefaultAuthMethod().toString();
				log.debug("User was authenticated via the default method for this relying party ("
						+ authenticationMethod + ").");
			} else {
				log.debug("User was authenticated via the method (" + authenticationMethod + ").");
			}

			SAMLSubject authNSubject = new SAMLSubject(nameId, null, null, null);

			// Is this artifact or POST?
			boolean artifactProfile = useArtifactProfile(descriptor, acceptanceURL, relyingParty);

			// SAML Artifact profile - don't even attempt this for legacy providers (they don't support it)
			if (artifactProfile) {
				respondWithArtifact(request, response, support, principal, relyingParty, descriptor, acceptanceURL,
						nameId, authenticationMethod, authNSubject);

				// SAML POST profile
			} else {
				respondWithPOST(request, response, support, principal, relyingParty, descriptor, acceptanceURL, nameId,
						authenticationMethod, authNSubject);
			}
		} catch (InvalidClientDataException e) {
			throw new RequestHandlingException("Unable to handle request.  Client data is invalid: " + e);
		} catch (NameIdentifierMappingException e) {
			log.error("Error converting principal to SAML Name Identifier: " + e);
			throw new RequestHandlingException("Unable to handle request.  Error recognizing principal.");
		} catch (SAMLException e) {
			log.error("Error creating SAML Response: " + e);
			throw new RequestHandlingException("Unalbe to handle request.  Error creating SAML Response.");
		}
	}

	private void respondWithArtifact(HttpServletRequest request, HttpServletResponse response,
			IdPProtocolSupport support, LocalPrincipal principal, RelyingParty relyingParty,
			EntityDescriptor descriptor, String acceptanceURL, SAMLNameIdentifier nameId, String authenticationMethod,
			SAMLSubject authNSubject) throws SAMLException, ServletException, RequestHandlingException {

		log.debug("Responding with Artifact profile.");
		ArrayList<SAMLAssertion> assertions = new ArrayList<SAMLAssertion>();

		authNSubject.addConfirmationMethod(SAMLSubject.CONF_ARTIFACT);
		assertions.add(generateAuthNAssertion(request, relyingParty, descriptor, nameId, authenticationMethod,
				getAuthNTime(request), authNSubject));

		// Package attributes for push, if necessary.
		if (pushAttributes(true, relyingParty)) {
			log.info("Resolving attributes for push.");
			generateAttributes(support, principal, relyingParty, assertions, request);
		}

		// Sign the assertions, if necessary
		boolean metaDataIndicatesSignAssertions = false;
		if (descriptor != null) {
			SPSSODescriptor sp = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
			if (sp != null) {
				if (sp.getWantAssertionsSigned()) {
					metaDataIndicatesSignAssertions = true;
				}
			}
		}
		if (relyingParty.wantsAssertionsSigned() || metaDataIndicatesSignAssertions) {
			support.signAssertions((SAMLAssertion[]) assertions.toArray(new SAMLAssertion[0]), relyingParty);
		}

		// Create artifacts for each assertion
		ArrayList<Artifact> artifacts = new ArrayList<Artifact>();
		for (int i = 0; i < assertions.size(); i++) {
			SAMLAssertion assertion = (SAMLAssertion) assertions.get(i);
			Artifact artifact = support.getArtifactMapper().generateArtifact(assertion, relyingParty);
			artifacts.add(artifact);

			// Put attributes names in the transaction log when it is set to DEBUG
			if (support.getTransactionLog().isDebugEnabled()) {
				Iterator statements = assertion.getStatements();
				while (statements.hasNext()) {
					SAMLStatement statement = (SAMLStatement) statements.next();
					if (statement instanceof SAMLAttributeStatement) {
						Iterator attributes = ((SAMLAttributeStatement) statement).getAttributes();
						StringBuffer attributeBuffer = new StringBuffer();
						while (attributes.hasNext()) {
							SAMLAttribute attribute = (SAMLAttribute) attributes.next();
							attributeBuffer.append("(" + attribute.getName() + ")");
							support.getTransactionLog().debug(
									"Artifact (" + artifact.encode() + ") created with the following attributes: "
											+ attributeBuffer.toString());
						}
					}
				}
			}
		}

		try {
			// Assemble the query string
			StringBuffer destination = new StringBuffer(acceptanceURL);
			destination.append("?TARGET=");

			destination.append(URLEncoder.encode(request.getParameter("target"), "UTF-8"));

			Iterator iterator = artifacts.iterator();
			StringBuffer artifactBuffer = new StringBuffer(); // Buffer for the transaction log

			// Construct the artifact query parameter
			while (iterator.hasNext()) {
				Artifact artifact = (Artifact) iterator.next();
				artifactBuffer.append("(" + artifact.encode() + ")");
				destination.append("&SAMLart=");
				destination.append(URLEncoder.encode(artifact.encode(), "UTF-8"));
			}

			log.debug("Redirecting to (" + destination.toString() + ").");

			response.sendRedirect(destination.toString());

			// Redirect to the artifact receiver
			support.getTransactionLog().info(
					"Assertion artifact(s) (" + artifactBuffer.toString() + ") issued to provider ("
							+ relyingParty.getProviderId() + ") on behalf of principal (" + principal.getName()
							+ "). Name Identifier: (" + nameId.getName() + "). Name Identifier Format: ("
							+ nameId.getFormat() + ").");
		} catch (UnsupportedEncodingException e) {
			log.error("Error encoding URL: " + e);
			throw new RequestHandlingException("Unable to handle request.  URL Encoder malfuntion.");
		} catch (IOException e) {
			log.error("Error issuing redirect: " + e);
			throw new ServletException(e);
		}
	}

	public static boolean pushAttributeDefault = false;

	private void respondWithPOST(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support,
			LocalPrincipal principal, RelyingParty relyingParty, EntityDescriptor descriptor, String acceptanceURL,
			SAMLNameIdentifier nameId, String authenticationMethod, SAMLSubject authNSubject) throws SAMLException,
			ServletException {

		log.debug("Responding with POST profile.");
		ArrayList<SAMLAssertion> assertions = new ArrayList<SAMLAssertion>();
		authNSubject.addConfirmationMethod(SAMLSubject.CONF_BEARER);
		assertions.add(generateAuthNAssertion(request, relyingParty, descriptor, nameId, authenticationMethod,
				getAuthNTime(request), authNSubject));

		// Package attributes for push, if necessary.
		if (pushAttributes(pushAttributeDefault, relyingParty)) {
			log.info("Resolving attributes for push.");
			generateAttributes(support, principal, relyingParty, assertions, request);
		}

		// Sign the assertions, if necessary
		boolean metaDataIndicatesSignAssertions = false;
		if (descriptor != null) {
			SPSSODescriptor sp = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
			if (sp != null) {
				if (sp.getWantAssertionsSigned()) {
					metaDataIndicatesSignAssertions = true;
				}
			}
		}
		if (relyingParty.wantsAssertionsSigned() || metaDataIndicatesSignAssertions) {
			support.signAssertions((SAMLAssertion[]) assertions.toArray(new SAMLAssertion[0]), relyingParty);
		}

		// Set attributes needed by form
		request.setAttribute("acceptanceURL", acceptanceURL);
		request.setAttribute("target", request.getParameter("target"));

		SAMLResponse samlResponse = new SAMLResponse(null, acceptanceURL, assertions, null);

		support.signResponse(samlResponse, relyingParty);

		try {
			createPOSTForm(request, response, samlResponse.toBase64());
		} catch (IOException e) {
			log.error("Error creating POST Form: " + e);
			throw new ServletException(e);
		}

		// Make transaction log entry
		support.getTransactionLog().info(
				"Authentication assertion issued to provider (" + relyingParty.getProviderId()
						+ ") on behalf of principal (" + principal.getName() + "). Name Identifier: ("
						+ nameId.getName() + "). Name Identifier Format: (" + nameId.getFormat() + ").");

	}

	private void generateAttributes(IdPProtocolSupport support, LocalPrincipal principal, RelyingParty relyingParty,
			ArrayList<SAMLAssertion> assertions, HttpServletRequest request) throws SAMLException {

		try {
			Collection<? extends SAMLAttribute> attributes = support.getReleaseAttributes(principal, relyingParty,
					relyingParty.getProviderId());
			log.info("Found " + attributes.size() + " attribute(s) for " + principal.getName());

			// Bail if we didn't get any attributes
			if (attributes == null || attributes.size() < 1) {
				log.info("No attributes resolved.");
				return;
			}

			// Reference requested subject
			SAMLSubject attrSubject = (SAMLSubject) ((SAMLSubjectStatement) ((SAMLAssertion) assertions.get(0))
					.getStatements().next()).getSubject().clone();

			// May be one assertion or two.
			if (relyingParty.singleAssertion()) {
				log.debug("merging attributes into existing authn assertion");
				// Put all attributes into an assertion
				((SAMLAssertion) assertions.get(0)).addStatement(new SAMLAttributeStatement(attrSubject, Arrays
						.asList(attributes)));

				if (log.isDebugEnabled()) {
					log.debug("Dumping combined Assertion:" + System.getProperty("line.separator")
							+ assertions.get(0).toString());
				}
			} else {
				ArrayList<String> audiences = new ArrayList<String>();
				if (relyingParty.getProviderId() != null) {
					audiences.add(relyingParty.getProviderId());
				}
				if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
					audiences.add(relyingParty.getName());
				}
				String remoteProviderId = request.getParameter("providerId");
				if (remoteProviderId != null && !remoteProviderId.equals("") && !audiences.contains(remoteProviderId)) {
					audiences.add(remoteProviderId);
				}

				SAMLCondition condition = new SAMLAudienceRestrictionCondition(audiences);

				// Put all attributes into an assertion
				SAMLStatement statement = new SAMLAttributeStatement(attrSubject, attributes);

				// Set assertion expiration to longest attribute expiration
				long max = 0;
				for (SAMLAttribute attribute : attributes) {
					if (max < attribute.getLifetime()) {
						max = attribute.getLifetime();
					}
				}
				Date now = new Date();
				Date then = new Date(now.getTime() + (max * 1000)); // max is in seconds

				SAMLAssertion attrAssertion = new SAMLAssertion(relyingParty.getIdentityProvider().getProviderId(),
						now, then, Collections.singleton(condition), null, Collections.singleton(statement));
				assertions.add(attrAssertion);

				if (log.isDebugEnabled()) {
					log.debug("Dumping generated Attribute Assertion:" + System.getProperty("line.separator")
							+ attrAssertion.toString());
				}
			}
		} catch (AAException e) {
			log.error("An error was encountered while generating assertion for attribute push: " + e);
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		} catch (CloneNotSupportedException e) {
			log.error("An error was encountered while generating assertion for attribute push: " + e);
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}
	}

	private SAMLAssertion generateAuthNAssertion(HttpServletRequest request, RelyingParty relyingParty,
			EntityDescriptor descriptor, SAMLNameIdentifier nameId, String authenticationMethod, Date authTime,
			SAMLSubject subject) throws SAMLException {

		// Determine the correct audiences
		ArrayList<String> audiences = new ArrayList<String>();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
			audiences.add(relyingParty.getName());
		}
		String remoteProviderId = request.getParameter("providerId");
		if (remoteProviderId != null && !remoteProviderId.equals("") && !audiences.contains(remoteProviderId)) {
			audiences.add(remoteProviderId);
		}

		// Determine the correct issuer
		String issuer = relyingParty.getIdentityProvider().getProviderId();

		ArrayList<SAMLAuthorityBinding> bindings = new ArrayList<SAMLAuthorityBinding>();

		// Create the assertion
		Vector<SAMLCondition> conditions = new Vector<SAMLCondition>(1);
		if (audiences != null && audiences.size() > 0) conditions.add(new SAMLAudienceRestrictionCondition(audiences));

		SAMLStatement[] statements = {new SAMLAuthenticationStatement(subject, authenticationMethod, authTime, request
				.getRemoteAddr(), null, bindings)};

		SAMLAssertion assertion = new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(System
				.currentTimeMillis() + 300000), conditions, null, Arrays.asList(statements));

		if (log.isDebugEnabled()) {
			log.debug("Dumping generated AuthN Assertion:" + System.getProperty("line.separator")
					+ assertion.toString());
		}

		return assertion;
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "Shibboleth v1.x SSO";
	}

	private void validateShibSpecificData(HttpServletRequest request) throws InvalidClientDataException {

		if (request.getParameter("target") == null || request.getParameter("target").equals("")) { throw new InvalidClientDataException(
				"Invalid data from Service Provider: no target URL received."); }
		if ((request.getParameter("shire") == null) || (request.getParameter("shire").equals(""))) { throw new InvalidClientDataException(
				"Invalid data from Service Provider: No acceptance URL received."); }
	}

	private static void createPOSTForm(HttpServletRequest req, HttpServletResponse res, byte[] buf) throws IOException,
			ServletException {

		// Hardcoded to ASCII to ensure Base64 encoding compatibility
		req.setAttribute("assertion", new String(buf, "ASCII"));

		if (log.isDebugEnabled()) {
			log.debug("Dumping generated SAML Response:" + System.getProperty("line.separator")
					+ new String(Base64.decode(buf)));
		}

		RequestDispatcher rd = req.getRequestDispatcher("/IdP.jsp");
		rd.forward(req, res);
	}

	/**
	 * Boolean indication of which browser profile is in effect. "true" indicates Artifact and "false" indicates POST.
	 */
	private static boolean useArtifactProfile(EntityDescriptor descriptor, String acceptanceURL,
			RelyingParty relyingParty) {

		boolean artifactMeta = false;
		boolean postMeta = false;

		// Look at the metadata bindings, if we can find them
		if (descriptor != null) {
			SPSSODescriptor sp = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);

			if (sp != null) {

				// See if this is the default endpoint location.
				AssertionConsumerService defaultEndpoint = sp.getDefaultAssertionConsumerService();
				if (defaultEndpoint != null && defaultEndpoint.getLocation().equals(acceptanceURL)) {
					// If we recognize the default binding, this is the one to use.
					if (defaultEndpoint.getBinding().equals(SAMLBrowserProfile.PROFILE_POST_URI)) return false;
					else if (defaultEndpoint.getBinding().equals(SAMLBrowserProfile.PROFILE_ARTIFACT_URI)) return true;
				}
				// If not, look through everything we have
				List<AssertionConsumerService> endpoints = sp.getAssertionConsumerServices();
				for (AssertionConsumerService ep : endpoints) {
					if (acceptanceURL.equals(ep.getLocation())
							&& SAMLBrowserProfile.PROFILE_POST_URI.equals(ep.getBinding())) {
						log.debug("Metadata indicates support for POST profile.");
						postMeta = true;
						continue;
					}
				}

				endpoints = sp.getAssertionConsumerServices();
				for (AssertionConsumerService ep : endpoints) {
					if (acceptanceURL.equals(ep.getLocation())
							&& SAMLBrowserProfile.PROFILE_ARTIFACT_URI.equals(ep.getBinding())) {
						log.debug("Metadata indicates support for Artifact profile.");
						artifactMeta = true;
						continue;
					}
				}
			}
		}

		// If we have metadata for both, use the relying party default
		if (!(artifactMeta && postMeta)) {

			// If we only have metadata for one, use it
			if (artifactMeta) { return true; }
			if (postMeta) { return false; }

		}

		// If we have missing or incomplete metadata, use relying party default
		if (relyingParty.defaultToPOSTProfile()) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Boolean indication of whether an assertion containing an attribute statement should be bundled in the response
	 * with the assertion containing the AuthN statement.
	 */
	private static boolean pushAttributes(boolean artifactProfile, RelyingParty relyingParty) {

		// By default push for Artifact and don't push for POST
		// This can be overriden at the level of the relying party
		if (relyingParty.forceAttributePush()) {
			return true;
		} else if (relyingParty.forceAttributeNoPush()) {
			return false;
		} else if (artifactProfile) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Boolean indication of whethere or not a given assertion consumer URL is valid for a given SP.
	 */
	private static boolean isValidAssertionConsumerURL(EntityDescriptor descriptor, String shireURL)
			throws InvalidClientDataException {

		SPSSODescriptor sp = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
		if (sp == null) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}

		List<AssertionConsumerService> endpoints = sp.getAssertionConsumerServices();
		for (AssertionConsumerService endpoint : endpoints) {
			if (shireURL.equals(endpoint.getLocation())) { return true; }
		}
		log.info("Supplied consumer URL not found in metadata.");
		return false;
	}
}