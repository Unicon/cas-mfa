<jsp:directive.include file="includes/top.jsp"/>
<script src="<c:url value='js/duo/Duo-Web-v1.bundled.min.js'/>"></script>
<script>
    Duo.init({
        'host': '${apiHost}',
        'sig_request': '${sigRequest}',
        'post_argument': 'signedDuoResponse'
    });
</script>

<div id="msg" class="info">
    <h2><spring:message code="service.mfa.service.mfa.inprogress.header" /></h2>
    <h4><spring:message code="service.mfa.service.mfa.inprogress.message"
                        arguments="${service.authenticationMethod},${service}"
                        htmlEscape="true" /></h4>
</div>

<form:form method="post" id="duo_form" cssClass="fm-v clearfix" commandName="${commandName}" htmlEscape="true">
    <input type="hidden" name="lt" value="${loginTicket}"/>
    <input type="hidden" name="execution" value="${flowExecutionKey}"/>
    <input type="hidden" name="_eventId" value="submit"/>

    <div class="box fl-panel" id="login">
        <iframe id="duo_iframe" width="100%" height="330" frameborder="0"></iframe>
    </div>

    <p>
    <a href="javascript:void" onclick="redirectToLoginViewAndEndTheFlow();">
        <spring:message code="screen.mfa.button.cancel" />
    </a>
    </p>
</form:form>

<script>
    $(document).ready(function(){
        $("input#password").focus();
    });

    function redirectToLoginViewAndEndTheFlow() {
        var loginViewUrl = window.location.href;
        window.location.replace(loginViewUrl);
    }
</script>

<jsp:directive.include file="includes/bottom.jsp"/>
