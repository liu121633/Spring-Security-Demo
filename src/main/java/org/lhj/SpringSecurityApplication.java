package org.lhj;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringApplicationRunListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author 刘洪君
 * @date 2019/8/1 16:20
 */
@Slf4j
@SpringBootApplication
public class SpringSecurityApplication implements ApplicationRunner {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @Value("${server.port}")
    String port;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("http://127.0.0.1:" + port);
    }
}
