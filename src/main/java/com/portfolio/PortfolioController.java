package com.portfolio;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

@Controller
public class PortfolioController {

    @GetMapping("/")
    public String index(Model model) {
        List<Project> projects = List.of(
            new Project("Cloud Automation Tool", "A Java-based CLI for managing AWS resources.", "Java, Spring Boot, AWS SDK"),
            new Project("Real-time Analytics", "Dashboard for monitoring server health and traffic.", "Spring Boot, WebSockets, Thymeleaf"),
            new Project("Microservices Hub", "An API gateway and service discovery prototype.", "Java, Spring Cloud, Docker")
        );
        
        model.addAttribute("name", "Alex Developer");
        model.addAttribute("title", "Full Stack Software Engineer");
        model.addAttribute("projects", projects);
        return "index";
    }

    public record Project(String title, String description, String technologies) {}
}
