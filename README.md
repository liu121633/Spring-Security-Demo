# Spring-Security-Demo
# 做了什么
    这是一个spring security 跟spring boot 集成使用的demo
    我修改了spring security原来的认证方式 改用我自己写的认证Controller 
    在认证成功后我会返回一个token 而不是使用http session的方式
    每次请求我会去检查token 来构建 security context
    
    而RBAC权限方面 我将使用URL 进行鉴权

                                    - 是的 我就是这么干的
