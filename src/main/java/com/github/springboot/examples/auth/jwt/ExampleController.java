package com.github.springboot.examples.auth.jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("example")
@RestController
public class ExampleController {

    /**
     * Example endpoint.
     *
     * @return an arbitrary example string
     */
    @GetMapping(value="hello", produces = "application/json")
    public String exampleEndpoint(){
        return "hi!";
    }
}
