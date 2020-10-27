package com.eh.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    // 定制授权规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //定制请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启自动配置的登陆功能，效果，如果没有登陆，没有权限就会来到登陆页面
        http.formLogin().usernameParameter("user").passwordParameter("pwd")
                .loginPage("/userlogin");
        //1、/login来到登陆页
        //2、重定向到/login?error表示登陆失败
        //3、更多详细规定
        //4、默认post形式的 /login代表处理登陆
        //5、一但定制loginPage；那么 loginPage的post请求就是登陆


        //开启自动配置的注销功能。
        http.logout().logoutSuccessUrl("/");//注销成功以后来到首页
        //1、访问 /logout 表示用户注销，清空session
        //2、注销成功会返回 /login?logout 页面；

        //开启记住我功能
        http.rememberMe().rememberMeParameter("remeber");
        //登陆成功以后，将cookie发给浏览器保存，以后访问页面带上这个cookie，只要通过检查就可以免登录
        //点击注销会删除cookie

    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        // 默认定义用户存在内存中，实际开发存在数据库中auth.jdbcAuthentication()
        /**
         * 和其他加密方式相比，BCryptPasswordEncoder有着它自己的优势所在，首先加密的hash值每次都不同，就像md5的盐值加密一样，
         * 只不过盐值加密用到了随机数，前者用到的是其内置的算法规则，毕竟随机数没有设合适的话还是有一定几率被攻破的。
         * 其次BCryptPasswordEncoder的生成加密存储串也有60位之多。最重要的一点是，md5的加密不是spring security所推崇的加密方式了，
         * 所以我们还是要多了解点新的加密方式。
         *
         * 通过传入的值进行BCryptPasswordEncoder加密，然后获取，再保存。
         *
         * 由于每次的hash值都不同，导致加密密文都不一样，其实这才是我们所希望看到的，而不是千篇一律。
         *
         * 通过加密密文后，密码可以加密了，但是我们会发现输入123456的密码进行登录时登录不了的，为什么？
         * 因为它识别不了我们加密密文和明文之间的转换，你需要告诉spring，我已经将明文进行转换,
         * 这里使用new BCryptPasswordEncoder().encode("密码")来解决
         */
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123")).roles("VIP1", "VIP2")
                .and()
                .withUser("lisi").password(new BCryptPasswordEncoder().encode("123")).roles("VIP2", "VIP3")
                .and()
                .withUser("wangwu").password(new BCryptPasswordEncoder().encode("123")).roles("VIP1", "VIP3");

    }
}
