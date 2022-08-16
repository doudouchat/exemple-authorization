package com.exemple.authorization.core.swagger;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;

import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.spring.web.plugins.WebMvcRequestHandlerProvider;

@Configuration
public class SwaggerConfiguration {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2).select().apis(RequestHandlerSelectors.any()).paths(PathSelectors.any()).build();
    }

    @Bean
    public static BeanPostProcessor springfoxHandlerProviderBeanPostProcessor() {
        return new BeanPostProcessor() {

            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof WebMvcRequestHandlerProvider) {
                    overrideHandlerMappings(bean);
                }
                return bean;
            }

            private void overrideHandlerMappings(Object bean) {
                List<RequestMappingInfoHandlerMapping> originalHandlerMappings = getHandlerMappings(bean);
                List<RequestMappingInfoHandlerMapping> overrideHandlerMappings = originalHandlerMappings.stream()
                        .filter(mapping -> mapping.getPatternParser() == null)
                        .collect(Collectors.toList());
                originalHandlerMappings.clear();
                originalHandlerMappings.addAll(overrideHandlerMappings);
            }

        };
    }

    @SuppressWarnings("unchecked")
    private static <T> T getHandlerMappings(Object bean) {
        var field = ReflectionUtils.findField(bean.getClass(), "handlerMappings");
        ReflectionUtils.makeAccessible(field);
        return (T) ReflectionUtils.getField(field, bean);
    }
}
