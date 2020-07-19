package com.zhangwei.epinv.config;

import com.zhangwei.epinv.AppLauncher;
import org.springframework.boot.builder.SpringApplicationBuilder;
//import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

public class SpringBootAppServletInitializer
    //extends SpringBootServletInitializer
{
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(AppLauncher.class);
    }
}
