package com.boot.zuul;

import com.boot.zuul.config.TokenFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

@EnableDiscoveryClient
@EnableZuulProxy
@SpringBootApplication
public class BootZuulApplication {

	public static void main(String[] args) {
		SpringApplication.run(BootZuulApplication.class, args);
	}

	@Bean
	public TokenFilter tokenFilter() {
		return new TokenFilter();
	}
}
