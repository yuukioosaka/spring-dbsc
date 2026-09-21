package click.yukio.dbsc.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The two HTML pages. Both are plain server-rendered views; the JSON surface the
 * demo exercises lives in {@link DemoController}.
 */
@Controller
class DemoPages {

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/app")
    String app() {
        return "app";
    }
}
