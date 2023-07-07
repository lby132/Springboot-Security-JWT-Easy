package com.cos.jwtex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true); //내 서버가 응답을 할때 json을 자바스크립트에서 처리할 수 있게 할지 설정하는 것 예를들면 ajax나 axios로 데이터를 요청하고 응답을 자바스크립트로 받을수 있을지 없을지 서버에서 결정하는것.
                                       //false이면 자바스크립트로 어떤 요청을 했을때 응답이 오지 않음
      config.addAllowedOrigin("*"); // 모든 ip에 응답을 허용하겠다.
      config.addAllowedHeader("*"); // 모든 header에 응답을 허용하겠다.
      config.addAllowedMethod("*"); // 모든 post, get, put, delete, fetch 등 http 메서드를 허용하겠다.

      source.registerCorsConfiguration("/api/**", config);
      return new CorsFilter(source);
   }

}
