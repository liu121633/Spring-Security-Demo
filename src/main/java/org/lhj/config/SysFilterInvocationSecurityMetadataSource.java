package org.lhj.config;

import org.lhj.doman.entity.UrlEntity;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author 刘洪君
 * @date 2019/8/1 21:30
 */
@Service
public class SysFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource, ApplicationRunner {

    private Map<UrlEntity, List<ConfigAttribute>> permissions = new HashMap<>();


    @Override
    public void run(ApplicationArguments args) throws Exception {

        //添加日志
        this.permissions
                .put(new UrlEntity("/log", "POST"),
                        SecurityConfig.createList("ROLE_ADMIN", "ROLE_USER"));

        //查看日志
        this.permissions
                .put(new UrlEntity("/log", "GET"),
                        SecurityConfig.createList("ROLE_ADMIN"));

        //查看单个日志
        this.permissions
                .put(new UrlEntity("/log/{id}", "GET"),
                        SecurityConfig.createList("ROLE_ADMIN"));

    }


    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //object 中包含用户请求的request 信息
        HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
        //内存版
        return permissions.keySet()
                .parallelStream()
                .filter(url -> new AntPathRequestMatcher(url.getUri(), url.getHttpMethod()).matches(request))
                .findFirst()
                .map(resUrl -> permissions.get(resUrl))
                .orElse(null);
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }


}
