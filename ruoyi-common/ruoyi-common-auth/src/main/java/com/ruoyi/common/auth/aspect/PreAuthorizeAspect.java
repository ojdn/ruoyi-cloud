package com.ruoyi.common.auth.aspect;

import java.lang.reflect.Method;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.ruoyi.common.auth.annotation.HasPermissions;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.exception.ForbiddenException;
import com.ruoyi.common.utils.ServletUtils;
import com.ruoyi.system.feign.RemoteMenuService;

import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
public class PreAuthorizeAspect
{
    @Autowired
    private RemoteMenuService sysMenuClient;

    /**
     * 通过注解表达式去获取注解方法位置
     * @param point
     * @return
     * @throws Throwable
     */
    @Around("@annotation(com.ruoyi.common.auth.annotation.HasPermissions)")
    public Object around(ProceedingJoinPoint point) throws Throwable
    {

        Signature signature = point.getSignature();//获取签名
        MethodSignature methodSignature = (MethodSignature) signature;//通过签名获取方法的一系列数据,方法名,参数
        Method method = methodSignature.getMethod();//获取反射的方法对象
        HasPermissions annotation = method.getAnnotation(HasPermissions.class);//通过反射获取方法上的注解
        if (annotation == null)
        {
            return point.proceed();
        }
        String authority = new StringBuilder(annotation.value()).toString();
        if (has(authority))
        {
            return point.proceed();
        }
        else
        {
            throw new ForbiddenException();
        }
    }

    private boolean has(String authority)
    {
        // 用超管帐号方便测试，拥有所有权限
        HttpServletRequest request = ServletUtils.getRequest();
        String tmpUserKey = request.getHeader(Constants.CURRENT_ID);
        if (Optional.ofNullable(tmpUserKey).isPresent())
        {
            Long userId = Long.valueOf(tmpUserKey);
            log.debug("userid:{}", userId);
            if (userId == 1L)
            {
                return true;
            }
            return sysMenuClient.selectPermsByUserId(userId).stream().anyMatch(authority::equals);
        }
        return false;
    }
}