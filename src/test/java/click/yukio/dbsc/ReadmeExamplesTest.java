package click.yukio.dbsc;

import click.yukio.dbsc.core.StorageAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Compiles the README's documented rule shapes. A snippet in a README is not compiled by
 * anything, and generic inference is exactly the kind of thing that silently rots there —
 * this file exists so the examples are checked by the build.
 */
@SpringBootTest(
        classes = RuleCompositionTest.TestApp.class,
        properties = {"dbsc.storage=memory"})
@AutoConfigureMockMvc
class ReadmeExamplesTest {

    @Autowired
    DbscService dbsc;

    @Autowired
    StorageAdapter storage;

    @Test
    void adminRuleWithAllOfCompiles() {
        // The README's "RIGHT" example, verbatim. The type witness is required: allOf
        // takes AuthorizationManager<T>... and nothing in the bare lambdas tells the
        // compiler what T is, so without it the non-generic overload is chosen and the
        // DBSC lambda does not fit it.
        AuthorizationManagers.<RequestAuthorizationContext>allOf(
                AuthenticatedAuthorizationManager.authenticated(),
                AuthorityAuthorizationManager.hasRole("ADMIN"),
                (authentication, context) ->
                        new AuthorizationDecision(dbsc.isProtected(context.getRequest())));
    }

    @Test
    void dbscOnlyRuleCompiles() {
        // The README's simpler example: a lambda plus a method reference is enough
        // context for T to be inferred, so no witness is needed here.
        AuthorizationManagers.<RequestAuthorizationContext>allOf(
                (authentication, context) ->
                        new AuthorizationDecision(dbsc.isProtected(context.getRequest())));
    }

    @Test
    void gettingStartedRuleCompiles() {
        // The Getting Started chain's /api/** rule, verbatim: authenticated alongside
        // the tier check, which is the pair adopters actually write. The witness is
        // load-bearing here too -- one lambda and one method reference still leave T
        // ambiguous, because AuthenticatedAuthorizationManager.authenticated() returns
        // an AuthorizationManager<Object>.
        AuthorizationManagers.<RequestAuthorizationContext>allOf(
                AuthenticatedAuthorizationManager.authenticated(),
                (authentication, context) -> new AuthorizationDecision(
                        dbsc.isProtected(context.getRequest())));
    }
}
