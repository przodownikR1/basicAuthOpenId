package pl.java.scalatech.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@ComponentScan(basePackages="pl.java.scalatech.security")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


  


    @Override
    public void configure(WebSecurity web) throws Exception {
        // @formatter:off
        web.ignoring().
        antMatchers("/assets/**")
        .antMatchers("/css/**")
        .antMatchers("/js/**")
        .antMatchers("/images/**")
        .antMatchers("/favicon.ico")
        .antMatchers("/webjars/**");
        // @formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().and().requiresChannel().anyRequest().requiresSecure();

       

        // @formatter:off
        http.httpBasic()
        .and()
        .csrf().disable().headers().disable()
          .authorizeRequests().antMatchers("/login","/logout","secContext","principal","/health").permitAll()
          .antMatchers("/simple/**").hasAnyRole("USER")
          .antMatchers("/api/admin/**").hasRole("ADMIN")
          .antMatchers("/actuator/**").hasRole("ADMIN")
          .antMatchers("/metrics/**").hasRole("ADMIN")
          .antMatchers("/info/**").hasRole("ADMIN")
          .antMatchers("/health/**").hasRole("ADMIN")
          .antMatchers("/trace/**").hasRole("ADMIN")
          .antMatchers("/dump/**").hasRole("ADMIN")
          .antMatchers("/shutdown/**").hasRole("ADMIN")
          .antMatchers("/beans/**").hasRole("ADMIN")
          .antMatchers("/env/**").hasRole("ADMIN")
          .antMatchers("/autoconfig/**").hasRole("ADMIN")


          .anyRequest().permitAll();
          // @formatter:on
    }

   @Autowired
    public void configureAuth(AuthenticationManagerBuilder auth) throws Exception {
     // @formatter:off

        auth.inMemoryAuthentication().withUser("przodownik").password("slawek").roles("USER").and()
                                     .withUser("admin").password("slawek").roles( "ADMIN");
     // @formatter:on
    }

}
