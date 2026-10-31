package com.ikoyski.webtools.authserver.security;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Entry point for the branded, static OAuth provider-selection page.
 * Spring Security keeps /login as its configured login URL; the page itself
 * is served as a static resource so it does not require a template engine.
 */
@Controller
public class LoginPageController {

    @GetMapping("/login")
    public String loginPage() {
        return "redirect:/login.html";
    }
}
