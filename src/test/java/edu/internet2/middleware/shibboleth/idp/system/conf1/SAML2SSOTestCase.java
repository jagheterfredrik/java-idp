/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.system.conf1;

import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

/**
 * 
 */
public class SAML2SSOTestCase extends BaseConf1TestCase {

    /** Tests initial leg of the SSO request where request is decoded and sent to the authentication engine. */
    public void testFirstAuthenticationLeg() throws Exception {
        MockHttpServletRequest servletRequest = buildServletRequest("urn:example.org:sp1");
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        HttpSession session = servletRequest.getSession();
        Saml2LoginContext loginContext = (Saml2LoginContext) session
                .getAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY);

        assertNotNull(loginContext);
        assertEquals(false, loginContext.getAuthenticationAttempted());
        assertEquals(false, loginContext.isForceAuthRequired());
        assertEquals(false, loginContext.isPassiveAuthRequired());
        assertEquals("/AuthnEngine", loginContext.getAuthenticationEngineURL());
        assertEquals("/saml2/POST/SSO", loginContext.getProfileHandlerURL());
        assertEquals("urn:example.org:sp1", loginContext.getRelyingPartyId());
        assertEquals(1, loginContext.getRequestedAuthenticationMethods().size());

        assertEquals("/AuthnEngine", servletResponse.getForwardedUrl());
    }

    /** Tests second leg of the SSO request where request returns to SSO handler and AuthN statement is generated. */
    public void testSecondAuthenticationLeg() throws Exception {
        MockHttpServletRequest servletRequest = buildServletRequest("urn:example.org:sp1");
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        HttpSession httpSession = servletRequest.getSession(true);
        httpSession.setAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY, buildLoginContext("urn:example.org:sp1"));

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("action=\"https://example.org/mySP\" method=\"post\""));
        assertTrue(response.contains("SAMLResponse"));
    }

    /** Tests that the handler correctly fails out if the SSO profile is not configured. */
    public void testAuthenticationWithoutConfiguredSSO() throws Exception{
        MockHttpServletRequest servletRequest = buildServletRequest("urn:example.org:BogusSP");
        
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        try {
            handler.processRequest(profileRequest, profileResponse);
            fail("Request processing expected to due to lack of configured SAML 2 SSO profile");
        } catch (ProfileException e) {

        }
    }

    protected MockHttpServletRequest buildServletRequest(String relyingPartyId) throws Exception{
        AuthnRequest authnRequest = buildAuthnRequest(relyingPartyId);
        String authnRequestString = getSamlRequestString(authnRequest);
        
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/saml2/POST/SSO");
        servletRequest.setParameter("SAMLRequest", Base64.encodeBytes(authnRequestString.getBytes()));

        return servletRequest;
    }

    protected Saml2LoginContext buildLoginContext(String relyingPartyId) throws Exception{
        AuthnRequest request = buildAuthnRequest(relyingPartyId);
        Saml2LoginContext loginContext = new Saml2LoginContext(relyingPartyId, null, request);
        loginContext.setAuthenticationInstant(new DateTime());
        loginContext.setAuthenticationMethod("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setPrincipalName("testUser");
        loginContext.setRelyingParty(relyingPartyId);

        return loginContext;
    }
    
    protected AuthnRequest buildAuthnRequest(String relyingPartyId) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingPartyId);

        SAMLObjectBuilder<AuthnRequest> authnRequestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = authnRequestBuilder.buildObject();
        request.setID("1");
        request.setIssueInstant(new DateTime());
        request.setIssuer(issuer);

        return request;
    }

    protected String getSamlRequestString(AuthnRequest request) throws MarshallingException {
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
        Element requestElem = marshaller.marshall(request);
        return XMLHelper.nodeToString(requestElem);
    }
}