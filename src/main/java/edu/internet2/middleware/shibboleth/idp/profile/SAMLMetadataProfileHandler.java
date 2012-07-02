/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile;

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.Charset;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;

/**
 * A simple profile handler that serves up the IdP's metadata. Eventually this handler should auto generate the metadata
 * but, for now, it just provides information from a static file.
 */
public class SAMLMetadataProfileHandler extends AbstractRequestURIMappedProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLMetadataProfileHandler.class);

    /** Metadata provider. */
    private FilesystemMetadataProvider metadataProvider;

    /**
     * Constructor.
     * 
     * @param metadataFile the IdPs metadata file
     * @param pool pool of XML parsers used to parse the metadata
     */
    public SAMLMetadataProfileHandler(String metadataFile, ParserPool pool) {
        try {
            metadataProvider = new FilesystemMetadataProvider(new File(metadataFile));
            metadataProvider.setParserPool(pool);
            metadataProvider.setRequireValidMetadata(false);
            metadataProvider.initialize();
        } catch (Exception e) {
            log.error("Unable to read metadata file " + metadataFile, e);
        }
    }

    /** {@inheritDoc} */
    public void processRequest(InTransport in, OutTransport out) throws ProfileException {
        XMLObject metadata;

        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) in).getWrappedRequest();
        HttpServletResponse httpResponse = ((HttpServletResponseAdapter) out).getWrappedResponse();

        String acceptHeder = DatatypeHelper.safeTrimOrNullString(httpRequest.getHeader("Accept"));
        if (acceptHeder != null && !acceptHeder.contains("application/samlmetadata+xml")) {
            httpResponse.setContentType("application/xml");
        } else {
            httpResponse.setContentType("application/samlmetadata+xml");
        }

        try {
            String requestedEntity =
                    DatatypeHelper.safeTrimOrNullString(((HttpServletRequestAdapter) in).getParameterValue("entity"));
            if (requestedEntity != null) {
                metadata = metadataProvider.getEntityDescriptor(requestedEntity);
            } else {
                metadata = metadataProvider.getMetadata();
            }

            if (metadata != null) {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(metadata);
                writeNode(marshaller.marshall(metadata), out.getOutgoingStream(), Charset.forName("UTF-8"));
            }
        } catch (Exception e) {
            log.error("Unable to retrieve and return metadata", e);
            throw new ProfileException(e);
        }
    }

    /**
     * Writes out the DOM node to a given output stream using a given output encoding.
     * 
     * @param node node to write out
     * @param output output stream to which the node is written
     * @param outputEncoding character encoding used by the serializer
     */
    private void writeNode(Node node, OutputStream output, Charset outputEncoding) {
        DOMImplementationLS domImplLS = XMLHelper.getLSDOMImpl(node);
        LSSerializer serializer = XMLHelper.getLSSerializer(domImplLS, null);

        LSOutput serializerOut = domImplLS.createLSOutput();
        serializerOut.setEncoding(outputEncoding.name());
        serializerOut.setByteStream(output);

        serializer.write(node, serializerOut);
    }
}