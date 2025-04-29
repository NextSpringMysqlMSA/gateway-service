package com.nsmm.esg.gatewayservice;

import com.nsmm.esg.gatewayservice.config.JwtAuthenticationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.web.server.WebFilter;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayServiceApplication.class, args);
	}

	@Bean
	public WebFilter jwtWebFilter(JwtAuthenticationFilter jwtAuthenticationFilter) {
		return jwtAuthenticationFilter;
	}
}
