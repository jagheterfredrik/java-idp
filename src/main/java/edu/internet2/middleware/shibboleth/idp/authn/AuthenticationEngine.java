/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.authn;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.authn.provider.PreviousSessionLoginHandler;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.session.impl.ServiceInformationImpl;

/**
 * Manager responsible for handling authentication requests.
 */
public class AuthenticationEngine extends HttpServlet {

    /** Name of the IdP Cookie containing the IdP session ID. */
    public static final String IDP_SESSION_COOKIE_NAME = "_idp_session";

    /** Serial version UID. */
    private static final long serialVersionUID = 8494202791991613148L;

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEngine.class);

    /** Profile handler manager. */
    private IdPProfileHandlerManager handlerManager;

    /** Session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        String handlerManagerId = config.getInitParameter("handlerManagerId");
        if (DatatypeHelper.isEmpty(handlerManagerId)) {
            handlerManagerId = "shibboleth.HandlerManager";
        }
        handlerManager = (IdPProfileHandlerManager) getServletContext().getAttribute(handlerManagerId);

        String sessionManagerId = config.getInitParameter("sessionManagedId");
        if (DatatypeHelper.isEmpty(sessionManagerId)) {
            sessionManagerId = "shibboleth.SessionManager";
        }

        sessionManager = (SessionManager<Session>) getServletContext().getAttribute(sessionManagerId);
    }

    /**
     * Returns control back to the authentication engine.
     * 
     * @param httpRequest current http request
     * @param httpResponse current http response
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Returning control to authentication engine");
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext == null) {
            LOG.error("User HttpSession did not contain a login context.  Unable to return to authentication engine");
            forwardRequest("/idp-error.jsp", httpRequest, httpResponse);
        } else {
            forwardRequest(loginContext.getAuthenticationEngineURL(), httpRequest, httpResponse);
        }
    }

    /**
     * Returns control back to the profile handler that invoked the authentication engine.
     * 
     * @param loginContext current login context
     * @param httpRequest current http request
     * @param httpResponse current http response
     */
    public static void returnToProfileHandler(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Returning control to profile handler at: {}", loginContext.getProfileHandlerURL());
        httpRequest.getSession().removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        httpRequest.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
        forwardRequest(loginContext.getProfileHandlerURL(), httpRequest, httpResponse);
    }

    /**
     * Forwards a request to the given path.
     * 
     * @param forwardPath path to forward the request to
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected static void forwardRequest(String forwardPath, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(forwardPath);
            dispatcher.forward(httpRequest, httpResponse);
            return;
        } catch (IOException e) {
            LOG.error("Unable to return control back to authentication engine", e);
        } catch (ServletException e) {
            LOG.error("Unable to return control back to authentication engine", e);
        }
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        LOG.debug("Processing incoming request");

        if (httpResponse.isCommitted()) {
            LOG.error("HTTP Response already committed");
        }

        LoginContext loginContext = (LoginContext) httpRequest.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext == null) {
            // When the login context comes from the profile handlers its attached to the request
            // The authn engine attaches it to the session to allow the handlers to do any number of
            // request/response pairs without maintaining or losing the login context
            loginContext = (LoginContext) httpRequest.getSession().getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        }

        if (loginContext == null) {
            LOG.error("Incoming request does not have attached login context");
            throw new ServletException("Incoming request does not have attached login context");
        }

        if (!loginContext.getAuthenticationAttempted()) {
            startUserAuthentication(loginContext, httpRequest, httpResponse);
        } else {
            completeAuthentication(loginContext, httpRequest, httpResponse);
        }
    }

    /**
     * Begins the authentication process. Determines if forced re-authentication is required or if an existing, active,
     * authentication method is sufficient. Also determines, when authentication is required, which handler to use
     * depending on whether passive authentication is required.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void startUserAuthentication(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Beginning user authentication process");
        try {
            Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            if (idpSession != null) {
                LOG.debug("Existing IdP session available for principal {}", idpSession.getPrincipalName());
            }

            Map<String, LoginHandler> possibleLoginHandlers = determinePossibleLoginHandlers(loginContext);
            LOG.debug("Possible authentication handlers for this request: {}", possibleLoginHandlers);

            // Filter out possible candidate login handlers by forced and passive authentication requirements
            if (loginContext.isForceAuthRequired()) {
                filterByForceAuthentication(idpSession, loginContext, possibleLoginHandlers);
            }

            if (loginContext.isPassiveAuthRequired()) {
                filterByPassiveAuthentication(idpSession, loginContext, possibleLoginHandlers);
            }

            // If the user already has a session and its usage is acceptable than use it
            // otherwise just use the first candidate login handler
            LOG.debug("Possible authentication handlers after filtering: {}", possibleLoginHandlers);
            if (idpSession != null && possibleLoginHandlers.containsKey(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX)) {
                authenticateUserWithPreviousSession(loginContext, possibleLoginHandlers, httpRequest, httpResponse);
            } else {
                possibleLoginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
                Entry<String, LoginHandler> chosenLoginHandler = possibleLoginHandlers.entrySet().iterator().next();
                authenticateUser(chosenLoginHandler.getKey(), chosenLoginHandler.getValue(), loginContext, httpRequest,
                        httpResponse);
            }
        } catch (AuthenticationException e) {
            loginContext.setAuthenticationFailure(e);
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
        }
    }

    /**
     * Determines which configured login handlers will support the requested authentication methods.
     * 
     * @param loginContext current login context
     * 
     * @return login methods that may be used to authenticate the user
     * 
     * @throws AuthenticationException thrown if no login handler meets the given requirements
     */
    protected Map<String, LoginHandler> determinePossibleLoginHandlers(LoginContext loginContext)
            throws AuthenticationException {
        Map<String, LoginHandler> supportedLoginHandlers = new HashMap<String, LoginHandler>(handlerManager
                .getLoginHandlers());
        LOG.trace("Supported login handlers: {}", supportedLoginHandlers);
        LOG.trace("Requested authentication methods: {}", loginContext.getRequestedAuthenticationMethods());

        // If no preferences Authn method preference is given, then we're free to use any
        if (loginContext.getRequestedAuthenticationMethods().isEmpty()) {
            LOG.trace("No preference given for authentication methods");
            return supportedLoginHandlers;
        }

        // Otherwise we need to filter all the mechanism supported by the IdP so that only the request types are left
        // Previous session handler is a special case, we always to keep that around if it's configured
        Iterator<Entry<String, LoginHandler>> supportedLoginHandlerItr = supportedLoginHandlers.entrySet().iterator();
        Entry<String, LoginHandler> supportedLoginHandler;
        while (supportedLoginHandlerItr.hasNext()) {
            supportedLoginHandler = supportedLoginHandlerItr.next();
            if (!supportedLoginHandler.getKey().equals(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX)
                    && !loginContext.getRequestedAuthenticationMethods().contains(supportedLoginHandler.getKey())) {
                supportedLoginHandlerItr.remove();
                continue;
            }
        }

        if (supportedLoginHandlers.isEmpty()) {
            LOG.error("No authentication method, requested by the service provider, is supported");
            throw new AuthenticationException(
                    "No authentication method, requested by the service provider, is supported");
        }

        return supportedLoginHandlers;
    }

    /**
     * Filters out any login handler based on the requirement for forced authentication.
     * 
     * During forced authentication any handler that has not previously been used to authenticate the user or any
     * handlers that have been and support force re-authentication may be used. Filter out any of the other ones.
     * 
     * @param idpSession user's current IdP session
     * @param loginContext current login context
     * @param loginHandlers login handlers to filter
     * 
     * @throws ForceAuthenticationException thrown if no handlers remain after filtering
     */
    protected void filterByForceAuthentication(Session idpSession, LoginContext loginContext,
            Map<String, LoginHandler> loginHandlers) throws ForceAuthenticationException {
        LOG.debug("Forced authentication is required, filtering possible login handlers accordingly");

        ArrayList<AuthenticationMethodInformation> activeMethods = new ArrayList<AuthenticationMethodInformation>();
        if (idpSession != null) {
            activeMethods.addAll(idpSession.getAuthenticationMethods().values());
        }

        loginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);

        LoginHandler loginHandler;
        for (AuthenticationMethodInformation activeMethod : activeMethods) {
            loginHandler = loginHandlers.get(activeMethod.getAuthenticationMethod());
            if (loginHandler != null && !loginHandler.supportsForceAuthentication()) {
                for (String handlerSupportedMethods : loginHandler.getSupportedAuthenticationMethods()) {
                    loginHandlers.remove(handlerSupportedMethods);
                }
            }
        }

        LOG.debug("Authentication handlers remaining after forced authentication requirement filtering: {}",
                loginHandlers);

        if (loginHandlers.isEmpty()) {
            LOG.error("Force authentication required but no login handlers available to support it");
            throw new ForceAuthenticationException();
        }
    }

    /**
     * Filters out any login handler that doesn't support passive authentication if the login context indicates passive
     * authentication is required.
     * 
     * @param idpSession user's current IdP session
     * @param loginContext current login context
     * @param loginHandlers login handlers to filter
     * 
     * @throws PassiveAuthenticationException thrown if no handlers remain after filtering
     */
    protected void filterByPassiveAuthentication(Session idpSession, LoginContext loginContext,
            Map<String, LoginHandler> loginHandlers) throws PassiveAuthenticationException {
        LOG.debug("Passive authentication is required, filtering poassible login handlers accordingly.");

        if (idpSession == null) {
            loginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
        }

        LoginHandler loginHandler;
        Iterator<Entry<String, LoginHandler>> authnMethodItr = loginHandlers.entrySet().iterator();
        while (authnMethodItr.hasNext()) {
            loginHandler = authnMethodItr.next().getValue();
            if (!loginHandler.supportsPassive()) {
                authnMethodItr.remove();
            }
        }

        LOG.debug("Authentication handlers remaining after passive authentication requirement filtering: {}",
                loginHandlers);

        if (loginHandlers.isEmpty()) {
            LOG.error("Passive authentication required but no login handlers available to support it");
            throw new PassiveAuthenticationException();
        }
    }

    /**
     * Completes the authentication request using an existing, active, authentication method for the current user.
     * 
     * @param loginContext current login context
     * @param possibleLoginHandlers login handlers that meet the peers authentication requirements
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void authenticateUserWithPreviousSession(LoginContext loginContext,
            Map<String, LoginHandler> possibleLoginHandlers, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Authenticating user by way of existing session.");

        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        PreviousSessionLoginHandler loginHandler = (PreviousSessionLoginHandler) handlerManager.getLoginHandlers().get(
                AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);

        AuthenticationMethodInformation authenticationMethod = null;
        for (String possibleAuthnMethod : idpSession.getAuthenticationMethods().keySet()) {
            authenticationMethod = idpSession.getAuthenticationMethods().get(possibleAuthnMethod);
            if (authenticationMethod != null) {
                break;
            }
        }

        if (loginHandler.reportPreviousSessionAuthnMethod()) {
            loginContext.setAuthenticationDuration(loginHandler.getAuthenticationDuration());
            loginContext.setAuthenticationInstant(new DateTime());
            loginContext.setAuthenticationMethod(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
        } else {
            loginContext.setAuthenticationDuration(authenticationMethod.getAuthenticationDuration());
            loginContext.setAuthenticationInstant(authenticationMethod.getAuthenticationInstant());
            loginContext.setAuthenticationMethod(authenticationMethod.getAuthenticationMethod());
        }
        loginContext.setPrincipalName(idpSession.getPrincipalName());

        loginContext.setAuthenticationAttempted();
        httpRequest.getSession().setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
        loginHandler.login(httpRequest, httpResponse);
    }

    /**
     * Authenticates the user with the given authentication method provided by the given login handler.
     * 
     * @param authnMethod the authentication method that will be used to authenticate the user
     * @param loginHandler login handler that will authenticate user
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void authenticateUser(String authnMethod, LoginHandler loginHandler, LoginContext loginContext,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Authenticating user with login handler of type {}", loginHandler.getClass().getName());

        loginContext.setAuthenticationAttempted();
        loginContext.setAuthenticationInstant(new DateTime());
        loginContext.setAuthenticationDuration(loginHandler.getAuthenticationDuration());
        loginContext.setAuthenticationMethod(authnMethod);
        loginContext.setAuthenticationEngineURL(HttpHelper.getRequestUriWithoutContext(httpRequest));
        httpRequest.getSession().setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
        loginHandler.login(httpRequest, httpResponse);
    }

    /**
     * Completes the authentication process.
     * 
     * The principal name set by the authentication handler is retrieved and pushed in to the login context, a
     * Shibboleth session is created if needed, information indicating that the user has logged into the service is
     * recorded and finally control is returned back to the profile handler.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void completeAuthentication(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Completing user authentication process");

        // We check if the principal name was already set in the login context
        // if not attempt to pull it from where login handlers are supposed to provide it
        String principalName = DatatypeHelper.safeTrimOrNullString(loginContext.getPrincipalName());
        if (principalName == null) {
            principalName = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                    .getAttribute(LoginHandler.PRINCIPAL_NAME_KEY));
            if (principalName != null) {
                loginContext.setPrincipalName(principalName);
            } else {
                loginContext.setPrincipalAuthenticated(false);
                loginContext.setAuthenticationFailure(new AuthenticationException(
                        "No principal name returned from authentication handler."));
                LOG.error("No principal name returned from authentication method: "
                        + loginContext.getAuthenticationMethod());
                returnToProfileHandler(loginContext, httpRequest, httpResponse);
                return;
            }
        }
        loginContext.setPrincipalAuthenticated(true);

        // We allow a login handler to override the authentication method in the event that it supports multiple methods
        String actualAuthnMethod = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (actualAuthnMethod != null) {
            loginContext.setAuthenticationMethod(actualAuthnMethod);
        }

        LOG.debug("User {} authenticated with method {}", loginContext.getPrincipalName(), loginContext
                .getAuthenticationMethod());
        updateUserSession(loginContext, httpRequest, httpResponse);
        returnToProfileHandler(loginContext, httpRequest, httpResponse);
    }

    /**
     * Updates the user's Shibboleth session with authentication information. If no session exists a new one will be
     * created.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void updateUserSession(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        if (idpSession == null) {
            LOG.debug("Creating shibboleth session for principal {}", loginContext.getPrincipalName());
            idpSession = (Session) sessionManager.createSession(loginContext.getPrincipalName());
            loginContext.setSessionID(idpSession.getSessionID());
            addSessionCookie(httpRequest, httpResponse, idpSession);
        }

        LOG.debug("Recording authentication and service information in Shibboleth session for principal: {}",
                loginContext.getPrincipalName());
        Subject subject = (Subject) httpRequest.getAttribute(LoginHandler.SUBJECT_KEY);
        String authnMethod = (String) httpRequest.getAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY);
        if (DatatypeHelper.isEmpty(authnMethod)) {
            authnMethod = loginContext.getAuthenticationMethod();
        }

        AuthenticationMethodInformation authnMethodInfo = new AuthenticationMethodInformationImpl(subject, authnMethod,
                loginContext.getAuthenticationInstant(), loginContext.getAuthenticationDuration());

        idpSession.getAuthenticationMethods().put(authnMethodInfo.getAuthenticationMethod(), authnMethodInfo);

        ServiceInformation serviceInfo = new ServiceInformationImpl(loginContext.getRelyingPartyId(), new DateTime(),
                authnMethodInfo);
        idpSession.getServicesInformation().put(serviceInfo.getEntityID(), serviceInfo);
    }

    /**
     * Adds an IdP session cookie to the outbound response.
     * 
     * @param httpRequest current request
     * @param httpResponse current response
     * @param userSession user's session
     */
    protected void addSessionCookie(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            Session userSession) {
        httpRequest.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, userSession);

        LOG.debug("Adding IdP session cookie to HTTP response");
        Cookie sessionCookie = new Cookie(IDP_SESSION_COOKIE_NAME, userSession.getSessionID());
        sessionCookie.setPath(httpRequest.getContextPath());
        sessionCookie.setSecure(false);
        sessionCookie.setMaxAge(-1);

        httpResponse.addCookie(sessionCookie);
    }
}