package S05T02.interactive_cv.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/")
public class ApiController {
    @GetMapping("login/hola")
    public Mono<String> sayHello(){
        return Mono.just("hola");
    }
}
