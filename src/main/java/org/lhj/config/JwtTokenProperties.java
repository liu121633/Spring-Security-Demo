package org.lhj.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author 刘洪君
 * @date 2019/8/1 16:29
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtTokenProperties {
    String header;
    String secret;
    Long expiration;
    String tokenHead;
}
