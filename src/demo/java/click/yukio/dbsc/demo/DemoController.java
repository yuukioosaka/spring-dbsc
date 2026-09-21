package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.Json;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The application endpoints the demo exercises.
 */
@RestController
@RequestMapping("/app")
class DemoController {

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
        body.put("note", "the login session was valid; DBSC did not inspect this request");
        body.put("receivedBody", rawBody);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
    }
}
