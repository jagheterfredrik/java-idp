<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginContext" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginHandler" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.session.*" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper" %>
<%@ page import="org.opensaml.saml2.metadata.*" %>

<%
    LoginContext loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
                                                                  application, request);
    Session userSession = HttpServletHelper.getUserSession(request);
%>

<html>

    <head>
        <title>Shibboleth Identity Provider - Login</title>
    </head>

	<body>
		<img src="<%= request.getContextPath() %>/images/logo.jpg" />
		<h2>Shibboleth Identity Provider Login to Service Provider <%= loginContext.getRelyingPartyId() %></h2>
		<p>
        Existing Session: <%= userSession != null %><br/>	
		Requested Authentication Methods: <%= loginContext.getRequestedAuthenticationMethods() %><br/>
		Attempting Authentication Method: <%= loginContext.getAttemptedAuthnMethod() %> <br/>
		Is Forced Authentication: <%= loginContext.isForceAuthRequired() %><br/>
		</p>
		
		<% if (request.getAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY) != null) { %>
		<p><font color="red">Authentication Failed</font></p>
		<% } %>
		
		<% if(request.getAttribute("actionUrl") != null){ %>
		    <form action="<%=request.getAttribute("actionUrl")%>" method="post">
		<% }else{ %>
		    <form action="j_security_check" method="post">
		<% } %>
		<table>
			<tr>
				<td>Username:</td>
				<td><input name="j_username" type="text" tabindex="1" /></td>
			</tr>
			<tr>
				<td>Password:</td>
				<td><input name="j_password" type="password" tabindex="2" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" value="Login" tabindex="3" /></td>
			</tr>
		</table>
		</form>
	</body>
	
</html>