package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.Session;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The application endpoints the demo exercises.
 */
@RestController
@RequestMapping("/app")
class DemoController {

    /** Stands in for the application's own session/TTL policy. */
    private static final long SESSION_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    private final DbscService dbsc;

    DemoController(DbscService dbsc) {
        this.dbsc = dbsc;
    }

    /**
     * A route on the authenticated side, to compare against the protocol routes.
     * It answers as long as the login cookie is valid — which is exactly the
     * request a stolen cookie can replay.
     */
    @GetMapping(path = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> whoami(HttpServletRequest request) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(Json.write(WhoamiReport.of(dbsc, request).asMap()));
    }

    /**
     * A POST route, so the CSRF mechanics of a JSON body can be exercised.
     */
    @PostMapping(path = "/payment", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> payment(@RequestBody(required = false) String rawBody) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "authorized");
        body.put("note", "the login session was valid and DBSC currently protects it");
        body.put("receivedBody", rawBody);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
    }

    /**
     * Re-binds the session the caller already holds, minting a fresh registration
     * token for the <em>same</em> DBSC session id.
     *
     * <p>A client may need a second registration opportunity on a session it is
     * already bound to — a prompt the user dismissed, a browser restart between the
     * login response and the POST, a token spent on a request that never landed.
     * The token is single-use by design, so a second attempt needs a new one, and
     * the library leaves that retry policy to the caller rather than exposing a
     * re-arm API. This route is that policy for the demo: it refuses nothing and
     * removes nothing, it just hands back a token for one more registration POST.
     * Whether the device already holds a key is decided at the registration route
     * itself, which is where a second registration is reported as
     * {@code SESSION_ALREADY_REGISTERED}.
     *
     * <p>Only {@code bind()} mints a token, so the session id must be read back from
     * the binding cookie and passed straight through: minting a new uuid here would
     * create a second session and lose the device key along with the first one.
     */
    @PostMapping(path = "/rebind", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> rebind(HttpServletRequest request, HttpServletResponse response) {
        Optional<Session> existing = dbsc.sessionFor(request);
        if (existing.isEmpty()) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "NO_SESSION");
            body.put("message", "nothing to re-bind: no DBSC binding cookie on this request");
            return ResponseEntity.status(409).contentType(MediaType.APPLICATION_JSON)
                    .body(Json.write(body));
        }

        Session session = existing.get();
        // Force the session to exist: a login always has one, and so does an
        // authenticated browser — but the caller here only needs to hold the DBSC
        // cookies, so nothing may be assumed about the HttpSession.
        String appSessionId = request.getSession().getId();
        dbsc.bind(session.id(), appSessionId, session.userId(), SESSION_TTL_MS, request, response);

        // The token bind() just minted is not returned by value, and calling
        // issueRegistrationToken() here would mint a second one that the response
        // header does not advertise. The header is the client's contract, so the
        // caller reads the path from Secure-Session-Registration instead; this body
        // only reports which session was re-bound.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionId", session.id());
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
    }
}
