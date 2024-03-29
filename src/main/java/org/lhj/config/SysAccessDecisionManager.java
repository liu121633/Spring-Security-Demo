package org.lhj.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Collection;

/**
 * @author 刘洪君
 * @date 2019/8/1 21:32
 */
@Service
public class SysAccessDecisionManager implements AccessDecisionManager {


    /**
     * //  decide 方法是判定是否拥有权限的决策方法，
     * //  authentication 是释CustomUserService中循环添加到 GrantedAuthority 对象中的权限信息集合.
     * //  object 包含客户端发起的请求的requset信息，可转换为 HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
     * //  configAttributes 为MyInvocationSecurityMetadataSource的getAttributes(Object object)这个方法返回的结果，此方法是为了判定用户请求的url
     * // 是否在权限表中，如果在权限表中，
     * // 则返回给 decide 方法，
     * // 用来判定用户是否有此权限。
     * // 如果不在权限表中则放行。
     */
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        //TODO 验证角色
        System.out.println(23);
        // if (null != configAttributes && configAttributes.size() > 0) {
        //     //当前登陆用户拥有的角色
        //     Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        //     //不支持游客访问
        //     if (new ArrayList<>(authorities).contains(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))) {
        //         throw new NoLoginException("你需要先登陆,才能使用这个功能！");
        //     }
        //     Long userId = ((SysUserDetails) authentication.getPrincipal()).getUserId();
        //     if (!sysJurisdictionService.isPossessOfApi(userId, new ArrayList<>(configAttributes).get(0).getAttribute())) {
        //         throw new NoPowerException("你未被授权访问这个接口!");
        //     }
        // }
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}