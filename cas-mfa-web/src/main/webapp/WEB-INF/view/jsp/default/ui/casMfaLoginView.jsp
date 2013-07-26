<%--
    Licensed to Jasig under one or more contributor license
    agreements. See the NOTICE file distributed with this work
    for additional information regarding copyright ownership.
    Jasig licenses this file to you under the Apache License,
    Version 2.0 (the "License"); you may not use this file
    except in compliance with the License.  You may obtain a
    copy of the License at the following location:

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

--%>
<jsp:directive.include file="includes/top.jsp" />

<div id="msg" class="info">
  <h2><spring:message code="service.mfa.service.mfa.inprogress.header" /></h2>
  <h4><spring:message code="service.mfa.service.mfa.inprogress.message" arguments="${service.authenticationMethod},${service}" /></h4>
</div>

<div class="box fl-panel" id="login">
  <form:form method="post" id="fm1" cssClass="fm-v clearfix"
    commandName="${commandName}" htmlEscape="true">
    <form:errors path="*" id="msg" cssClass="errors" element="div" />
    <!-- <spring:message code="screen.welcome.welcome" /> -->
    <h2>
      <spring:message code="screen.welcome.instructions" />
    </h2>
    <div class="row fl-controls-left">
      <label for="username" class="fl-label"><spring:message
          code="screen.welcome.label.netid" /></label>
      <c:if test="${not empty sessionScope.openIdLocalId}">
        <strong>${sessionScope.openIdLocalId}</strong>
        <input type="hidden" id="username" name="username"
          value="${sessionScope.openIdLocalId}" />
      </c:if>

      <c:if test="${empty sessionScope.openIdLocalId}">
        <spring:message code="screen.welcome.label.netid.accesskey"
          var="userNameAccessKey" />
         <form:input cssClass="required" cssErrorClass="error" id="username" size="25" tabindex="2"
          accesskey="${userNameAccessKey}" path="username" autocomplete="false" htmlEscape="true" 
          readonly="true" value="${mfaCredentials.principal}" />
      </c:if>
    </div>
    <div class="row fl-controls-left">
      <label for="password" class="fl-label"><spring:message code="screen.welcome.label.password" /></label>
      <spring:message code="screen.welcome.label.password.accesskey" var="passwordAccessKey" />
      <form:password cssClass="required" cssErrorClass="error" id="password" size="25" tabindex="1" path="password"
                     accesskey="${passwordAccessKey}" htmlEscape="true" autocomplete="off" />
    </div>
    <div class="row btn-row">
      <input type="hidden" name="lt" value="${loginTicket}" />
      <input type="hidden" name="execution" value="${flowExecutionKey}" /> 
      <input type="hidden" name="_eventId" value="submit" /> 
      <input  class="btn-submit" name="submit" accesskey="l" value="<spring:message code="screen.welcome.button.login" />"
              tabindex="4" type="submit" /> 
      <input class="btn-reset" name="reset" accesskey="c" value="<spring:message code="screen.welcome.button.clear" />"
              tabindex="5" type="reset" />    
    </div>
  </form:form>
</div>
<jsp:directive.include file="includes/bottom.jsp" />

<script>
$(document).ready(function(){
    $("input#password").focus();
});
</script>
