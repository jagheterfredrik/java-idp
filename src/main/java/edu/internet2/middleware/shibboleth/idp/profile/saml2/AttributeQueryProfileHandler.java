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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.util.ArrayList;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** SAML 2.0 Attribute Query profile handler. */
public class AttributeQueryProfileHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(AttributeQueryProfileHandler.class);

    /** Builder of assertion consumer service endpoints. */
    private SAMLObjectBuilder<AssertionConsumerService> acsEndpointBuilder;

    /** Constructor. */
    public AttributeQueryProfileHandler() {
        super();

        acsEndpointBuilder = (SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return AttributeQueryConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        Response samlResponse;

        AttributeQueryContext requestContext = null;

        try {
            requestContext = decodeRequest(inTransport, outTransport);
            
            if (requestContext.getProfileConfiguration() == null) {
                log.error("SAML 2 Attribute Query profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                        "SAML 2 Attribute Query profile is not configured for relying party "
                                + requestContext.getInboundMessageIssuer()));
                samlResponse = buildErrorResponse(requestContext);
            } else {
                checkSamlVersion(requestContext);

                // Resolve attribute query name id to principal name and place in context
                resolvePrincipal(requestContext);

                Session idpSession = getSessionManager().getSession(requestContext.getPrincipalName());
                if (idpSession != null) {
                    AuthenticationMethodInformation authnInfo = idpSession.getAuthenticationMethods().get(
                            requestContext.getInboundMessageIssuer());
                    if (authnInfo != null) {
                        requestContext.setPrincipalAuthenticationMethod(authnInfo.getAuthenticationMethod());
                    }
                }

                resolveAttributes(requestContext);
                requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());

                // Lookup principal name and attributes, create attribute statement from information
                ArrayList<Statement> statements = new ArrayList<Statement>();
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext);
                if (attributeStatement != null) {
                    statements.add(attributeStatement);
                }

                // create the SAML response
                samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
                        statements);
            }
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());

        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @return the created request context
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected AttributeQueryContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        log.debug("Decoding message with decoder binding {}", getInboundBinding());

        AttributeQueryContext requestContext = new AttributeQueryContext();
        requestContext.setCommunicationProfileId(getProfileId());

        MetadataProvider metadataProvider = getMetadataProvider();
        requestContext.setMetadataProvider(metadataProvider);

        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request");

            if (!(requestContext.getInboundSAMLMessage() instanceof AttributeQuery)) {
                log.error("Incoming message was not a AttributeQuery, it was a {}", requestContext
                        .getInboundSAMLMessage().getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Invalid SAML AttributeQuery message."));
                throw new ProfileException("Invalid SAML AttributeQuery message.");
            }

            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding attribute query message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error decoding message"));
            throw new ProfileException("Error decoding attribute query message");
        } catch (SecurityException e) {
            log.error("Message did not meet security requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Message did not meet security requirements"));
            throw new ProfileException("Message did not meet security requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            populateRequestContext(requestContext);
        }
    }

    /** {@inheritDoc} */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata = requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateAssertingPartyInformation(requestContext);

        EntityDescriptor localEntityDescriptor = requestContext.getLocalEntityMetadata();
        if (localEntityDescriptor != null) {
            requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /**
     * Populates the request context with information from the inbound SAML message.
     * 
     * This method requires the the following request context properties to be populated: inbound saml message
     * 
     * This methods populates the following request context properties: subject name identifier
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the inbound SAML message or subject identifier is null
     */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        AttributeQuery query = (AttributeQuery) requestContext.getInboundSAMLMessage();
        if (query != null) {
            Subject subject = query.getSubject();
            if (subject == null) {
                log.error("Attribute query did not contain a proper subject");
                ((AttributeQueryContext) requestContext).setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Attribute query did not contain a proper subject"));
                throw new ProfileException("Attribute query did not contain a proper subject");
            }
            requestContext.setSubjectNameIdentifier(subject.getNameID());
        }
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        Endpoint endpoint;

        if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            endpoint = acsEndpointBuilder.buildObject();
            endpoint.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        } else {
            BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
            endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
            endpointSelector.setMetadataProvider(getMetadataProvider());
            endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
            endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
            endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
            endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
            endpoint = endpointSelector.selectEndpoint();
        }

        return endpoint;
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            BaseSAML2ProfileRequestContext<AttributeQuery, Response, AttributeQueryConfiguration> {

    }
}