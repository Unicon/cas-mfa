package net.unicon.cas.mfa.web.flow;

/**
 * In the event that a left-over TGT exists from previous session, from which
 * an authentication context cannot be established, again, because the TGT is considered
 * invalid, this exception will be thrown.
 *<p>
 * In particular, the flow is to handle this exception and navigate to the
 * appropriate state, without requiring any additional action from the user
 * such as closing the browser to clearing the cache thereby killing the TGT.
 * The flow is responsible for handling this annoyance.
 *
 * <p>Essentially, the responsibility of this exception is solely to
 * communicate a broken and existing TGT, or in other words, the inability
 * to construct the authentication object from either the flow context
 * or an existing TGT. Beyond that task, it will not do
 * or provide any interesting functionality.
 * @author Misagh Moayyed
 * @see GenerateMultiFactorCredentialsAction
 */
public class NoAuthenticationContextAvailable extends RuntimeException {
    private static final long serialVersionUID = -1693098929280964735L;
}
