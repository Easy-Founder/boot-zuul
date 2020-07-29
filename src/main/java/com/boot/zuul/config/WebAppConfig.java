package com.boot.zuul.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Author chencl
 * @Date 2020/7/29 16:11
 * @Version 1.0
 * @Description
 */
@Configuration
public class WebAppConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        //设置允许跨域的路径
        registry.addMapping("/**")
                //设置允许跨域请求的域名
                .allowedOrigins("*")
                //设置允许跨域请求方式,或为allowedMethods("*")
                .allowedMethods("GET", "POST", "PUT", "OPTIONS", "DELETE")
                //是否允许证书 2.0不再默认开启
                .allowCredentials(true)
                //允许所有header
                .allowedHeaders("*")
                //跨域允许时间
                .maxAge(3600);
    }
}
