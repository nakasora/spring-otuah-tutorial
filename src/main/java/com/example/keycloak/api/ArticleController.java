package com.example.keycloak.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/articles")
public class ArticleController {

    private static final String ROLE_PREMIUM = "ROLE_premium_access";
    private static final Map<Long, Article> articles = createArticles();

    private static Map<Long, Article> createArticles() {
        Map<Long, Article> articles = new HashMap<>();

        articles.put(1L, new Article(1L, "Basic Article 1", "This is a basic article content", false));
        articles.put(2L, new Article(2L, "Basic Article 2", "This is another basic article content", false));
        articles.put(3L, new Article(3L, "Premium Article 1", "This is a premium article content", true));
        articles.put(4L, new Article(4L, "Premium Article 2", "This is another premium article content", true));

        return Collections.unmodifiableMap(articles);
    }

    @GetMapping("/basic")
    @PreAuthorize("hasAnyRole('basic_access', 'premium_access')")
    public List<Article> getBasicArticle() {
        return articles.values().stream()
                .filter(article -> !article.isPremium())
                .collect(Collectors.toList());
    }

    @GetMapping("/premium")
    @PreAuthorize("hasRole('premium_access')")
    public List<Article> getPremiumArticle() {
        return articles.values().stream()
                .filter(Article::isPremium)
                .collect(Collectors.toList());
    }

    @GetMapping("/all/{id}")
    public ResponseEntity<?> getArticById(@PathVariable Long id, Authentication authentication) {
        if (!articles.containsKey(id)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("This content may not found");
        }
        Article article = articles.get(id);
        if (article.isPremium()) {
            boolean isPremiumUser = authentication.getAuthorities().contains(new SimpleGrantedAuthority(ROLE_PREMIUM));
            if (isPremiumUser) {
                return ResponseEntity.ok(article);

            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("This content is only available for premium members");
            }
        }
        return ResponseEntity.ok(article);
    }
}