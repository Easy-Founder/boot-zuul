package com.boot.zuul.config;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;

/**
 * @program boot-zuul
 * @description: 鉴权
 * @author: zhangfan
 * @create: 2020/07/29 17:40
 */
@Slf4j
public class TokenFilter extends ZuulFilter {
	//开始时间
	private ThreadLocal<Long> startTime = new ThreadLocal<Long>();

	@Override
	public String filterType() {
		// 定义filter的类型，有pre、route、post、error四种,pre可以在请求被路由之前调用
		return FilterConstants.PRE_TYPE;
	}

	@Override
	public int filterOrder() {
		// filter执行顺序，通过数字指定 ,优先级为0，数字越大，优先级越低
		return FilterConstants.PRE_DECORATION_FILTER_ORDER ;
	}


	@Override
	public boolean shouldFilter() {
		// 是否执行该过滤器，此处为true，说明需要过滤
		return true;
	}

	@Override
	public Object run() throws ZuulException {
		startTime.set(System.currentTimeMillis());
		// 登录校验逻辑。
		// 1）获取Zuul提供的请求上下文对象
		RequestContext ctx = RequestContext.getCurrentContext();
		// 2) 从上下文中获取request对象
		HttpServletRequest req = ctx.getRequest();
		// 3) 从请求中获取token
		String token = req.getParameter("userToken");
		// 4) 判断
		if(token == null || "".equals(token.trim())){
			// 没有token，登录校验失败，拦截
			ctx.setSendZuulResponse(false);
			// 返回401状态码。也可以考虑重定向到登录页。
			ctx.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
		}
		// 校验通过，可以考虑把用户信息放入上下文，继续向后执行
		long times = System.currentTimeMillis() - startTime.get();
		log.info("结束请求 ==> 耗时:{}",times / 1000 );
		return null;
	}

}
