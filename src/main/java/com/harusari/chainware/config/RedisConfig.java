package com.harusari.chainware.config;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    @Value("${spring.data.redis.ssl.enabled:false}")
    private boolean redisSslEnabled;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(redisHost, redisPort);

        LettuceClientConfiguration clientConfig = redisSslEnabled ?
                LettuceClientConfiguration.builder().useSsl().build() :
                LettuceClientConfiguration.builder().build();

        return new LettuceConnectionFactory(config, clientConfig);
    }

    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }

    @Bean
    public RedissonClient redissonClient() {
        Config config = new Config();
        String protocol = redisSslEnabled ? "rediss://" : "redis://";
        config.useSingleServer()
                .setAddress(protocol + redisHost + ":" + redisPort)
                .setConnectionMinimumIdleSize(10)
                .setConnectionPoolSize(24)
                .setRetryAttempts(3)
                .setRetryInterval(1500)
                .setTimeout(6000);
        return Redisson.create(config);
    }

}