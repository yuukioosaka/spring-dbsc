package click.yukio.dbsc.demo;

import click.yukio.dbsc.config.DbscProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The two HTML pages. Both are plain server-rendered views; the JSON surface the
 * demo exercises lives in {@link DemoController}.
 */
@Controller
class DemoPages {

    private final DbscProperties properties;

    DemoPages(DbscProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/app")
    String app(Model model) {
        // Passed as a model attribute rather than read in the template with
        // ${@beanName...}: the auto-configuration registers DbscProperties under
        // its generated bean name, which is an implementation detail of
        // @EnableConfigurationProperties and not something a template should know.
        model.addAttribute("softEnabled", properties.getSoft().isEnabled());
        return "app";
    }
}
