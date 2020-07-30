package com.boot.zuul.config;

import com.alibaba.fastjson.JSONObject;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.http.ServletInputStreamWrapper;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.StringUtils;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.util.StreamUtils;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @program boot-zuul
 * @description: SQL注入拦截
 * @author: zhangfan
 * @create: 2020/07/29 16:58
 */
@Slf4j
public class SqLInjectionXSSFilter extends ZuulFilter {

	private static final CharSequence MULTIPART = "multipart";

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

	@Override
	public int filterOrder() {
		return FilterConstants.PRE_DECORATION_FILTER_ORDER - 2;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();
		log.info("--->>> SqLInjectionXSSFilter {},{}", request.getMethod(), request.getRequestURL().toString());
		StringBuilder params = new StringBuilder("?");
		Enumeration<String> names = request.getParameterNames();
		if( request.getMethod().equals("GET") ) {
			while (names.hasMoreElements()) {
				String name = (String) names.nextElement();
				params.append(name);
				params.append("=");
				params.append(request.getParameter(name));
				params.append("&");
			}
		}
		if (params.length() > 0) {
			params.delete(params.length()-1, params.length());
		}
		Enumeration<String> headers = request.getHeaderNames();
		boolean isUploadFile = false;
		while (headers.hasMoreElements()) {
			String name = (String) headers.nextElement();
			String value = request.getHeader(name);
			log.info("REQUESTHEADER: {}:{} ",name , value);
			if(value.contains(MULTIPART)) {
				isUploadFile = true;
			}
		}
		if(isUploadFile) {
			ctx.setSendZuulResponse(true); //对请求进行路由
			ctx.setResponseStatusCode(200);
			ctx.set("isSuccess", true);
			return null;
		}
		try {
			InputStream in = ctx.getRequest().getInputStream();

			String body = params.toString();
			body =	StreamUtils.copyToString(in, Charset.forName("UTF-8"));
			log.info("请求参数:{}",body);
			if(StringUtils.isEmpty(body)) {
				ctx.setSendZuulResponse(true); //对请求进行路由
				ctx.setResponseStatusCode(200);
				ctx.set("isSuccess", true);
				return null;
			}
			String newBody = "";
			Map<String, Object> stringObjectMap = cleanXSS(null==body?"":body);
			JSONObject json = (JSONObject) JSONObject.toJSON(stringObjectMap);
			// 如果存在sql注入,直接拦截请求
			newBody = json.toString();
			if (newBody.contains("forbid")) {
				log.info("sql 注入请求被拦截，直接返回");
				setUnauthorizedResponse(ctx);
			}

			final byte[] reqBodyBytes = newBody.getBytes();
			ctx.setRequest(new HttpServletRequestWrapper(request) {
				@Override
				public ServletInputStream getInputStream() throws IOException {
					return new ServletInputStreamWrapper(reqBodyBytes);
				}

				@Override
				public int getContentLength() {
					return reqBodyBytes.length;
				}

				@Override
				public long getContentLengthLong() {
					return reqBodyBytes.length;
				}
			});
		} catch (IOException e) {
			ctx.setSendZuulResponse(false); //不对其进行路由
			ctx.setResponseStatusCode(200);
			ctx.setResponseBody("{\"code\":500,\"message\":\"内部异常\",\"data\":null}");
			ctx.set("isSuccess", false);
			log.error("	xss，sql注入 过滤器发生异常",e);
		}
		return null;
	}


	private static Map<String, Object> cleanXSS(String value) {
		value = value.replaceAll("<", "& lt;").replaceAll(">", "& gt;");
		//value = value.replaceAll("\\(", "& #40;").replaceAll("\\)", "& #41;");
		//value = value.replaceAll("'", "& #39;");
		value = value.replaceAll("eval\\((.*)\\)", "");
		value = value.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");
		value = value.replaceAll("script", "");
		value = value.replaceAll("[*]", "[" + "*]");
		value = value.replaceAll("[+]", "[" + "+]");
		value = value.replaceAll("[?]", "[" + "?]");
		String badStr = "'|and|exec|execute|insert|select|delete|update|count|drop|%|chr|mid|master|truncate|"
				+ "char|declare|sitename|net user|xp_cmdshell|;|or|+|,|like'|and|exec|execute|insert|create|drop|"
				+ "table|from|grant|use|group_concat|column_name|"
				+ "information_schema.columns|table_schema|union|where|select|delete|update|order|by|count|"
				+ "chr|mid|master|truncate|char|declare|or|;|--|,|like|//|/|%|#";
		JSONObject json = JSONObject.parseObject(value);
		String[] badStrs = badStr.split("\\|");
		Map<String, Object> map = json;
		Map<String, Object> mapjson = new HashMap<>();
		for (Map.Entry<String, Object> entry : map.entrySet()) {
			Object valObj = entry.getValue();
			if(null == valObj) {
				continue;
			}
			String value1 = valObj.toString();
			for (String bad : badStrs) {
				if (value1.equalsIgnoreCase(bad)) {
					value1 = "forbid";
					mapjson.put(entry.getKey(), value1);
					break;
				} else {
					mapjson.put(entry.getKey(), entry.getValue());
				}
			}
		}
		return mapjson;
	}

	/** * 设置500拦截状态 */
	private void setUnauthorizedResponse(RequestContext ctx) {
		ctx.setSendZuulResponse(false); //不对其进行路由
		ctx.setResponseStatusCode(400);
		ctx.setResponseBody("{\"code\":500,\"message\":\"请求参数非法\",\"data\":null}");
		ctx.set("isSuccess", false);
	}
}
