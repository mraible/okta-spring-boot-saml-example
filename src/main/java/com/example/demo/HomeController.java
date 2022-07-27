package com.example.demo;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

    @RequestMapping("/")
    public String index() {
        return "home";
    }

    @RequestMapping("/hello")
    public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "hello";
    }

    public String index(Model model, @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        String emailAddress = principal.getFirstAttribute("email");
        model.addAttribute("emailAddress", emailAddress);
        model.addAttribute("userAttributes", principal.getAttributes());
        return "index";
    }

}
